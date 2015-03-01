
#include "fastpath.h"

static int mgr_sockfd;
static int neigh_sockfd;
struct thread_master *mgr_master;

#define FASTPATH_MSG_LENGTH 1472

static int rtattr_parse(struct rtattr *tb[], int maxattr, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr*)* (maxattr + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= maxattr)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
    return 0;
}

static int neigh_send(void *req)
{
    int ret = 0;
    struct module *route;
    struct msg_hdr resp;

    route = module_get_by_name("route");
    if (route == NULL) {
        fastpath_log_error("neigh_send: get route module failed\n");
        return -ENOENT;
    }

    ret = route->message(route, (struct msg_hdr *)req, &resp);

    return ret;
}

static int neigh_update(struct nlmsghdr *nlh)
{
    int err;
    struct arp_add arp;
    int len;
    struct ndmsg *ndm;
    struct rtattr *rta;
 	char *pifname;
	char if_name[IF_NAMESIZE];
    struct rtattr *tb[NDA_MAX+1];

    memset(&arp, 0, sizeof(struct arp_add));

    ndm = NLMSG_DATA(nlh);

    if (RTN_UNICAST != ndm->ndm_type){
        fastpath_log_debug("not support ~unicast now, type %d\n", ndm->ndm_type);
        return 0;
    }

    if (AF_INET != ndm->ndm_family && AF_INET6 != ndm->ndm_family) {
        fastpath_log_debug("family %d error.\n", ndm->ndm_family);
        return 0;
    }

 	pifname = if_indextoname(ndm->ndm_ifindex, if_name);
	if (pifname == NULL) {
		fastpath_log_error("%s:get if name by ifindex:%d err\n", 
                  __func__, ndm->ndm_ifindex);
		return -EIO;
	}

    // TODO: map ifindex to eif idx

#if 0
    if (!(ndm->ndm_state & (NUD_REACHABLE | NUD_PERMANENT))) {
        fastpath_log_debug( "ignore neigh state %08x.\n", ndm->ndm_state);
        return 0;
    }
#endif

    rta = (struct rtattr*)((char*)ndm + NLMSG_ALIGN(sizeof(struct ndmsg)));
    len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
    
    rtattr_parse(tb, NDA_MAX, rta, len);

    if (NULL == tb[NDA_DST]) {
        fastpath_log_error( "nda dst is null.\n");
        return -EINVAL;
    }

    arp.nh_iface = ndm->ndm_ifindex;
    memcpy(&arp.nh_ip, RTA_DATA(tb[NDA_DST]), RTA_PAYLOAD(tb[NDA_DST]));
    arp.type = NEIGH_TYPE_REACHABLE;
    if (NULL != tb[NDA_LLADDR]) {
        memcpy(&arp.nh_arp, (char*)RTA_DATA(tb[NDA_LLADDR]), RTA_PAYLOAD(tb[NDA_LLADDR]));
    }
    
    fastpath_log_debug( "%s: neigh update, family %d, ifidx %d, state 0x%02x,"
        "ip "NIPQUAD_FMT", lladdr "MAC_FMT"\n",
        __func__, ndm->ndm_family, ndm->ndm_ifindex, ndm->ndm_state, 
        HIPQUAD(arp.nh_ip), MAC_ARG(&arp.nh_arp));

    err = neigh_send(&arp);
    if (err != 0) {
        fastpath_log_error( "%s: send neigh failed\n", __func__);
    }

    return 0;
}

static int neigh_dispatch(struct nlmsghdr *hdr)
{
    int ret = 0;
    
    switch (hdr->nlmsg_type) {
        case RTM_NEWNEIGH:
        case RTM_DELNEIGH:
            ret = neigh_update(hdr);
            break;

        default:
            break;
    }
    
    return ret;
}

static int neigh_socket_receive(struct thread *thread)
{
    int status;
    char buf[8192];
    struct sockaddr_nl nladdr;
    struct iovec iov = { buf, sizeof(buf) };
    struct nlmsghdr *h;

    struct msghdr msg = {
        (void *)&nladdr, sizeof(nladdr),
        &iov, 1,
        NULL, 0,
        0
    };

    status = recvmsg(THREAD_FD(thread), &msg, 0);
    if (status < 0) {
        fastpath_log_error( "OVERRUN on rtnl socket");
        goto rtn;
    }
    if (status == 0) {
        fastpath_log_error( "EOF on rtnl socket");
        goto rtn;
    }
    if (msg.msg_namelen != sizeof(nladdr)) {
        fastpath_log_error( "invalid address size");
        goto rtn;
    }

    h = (struct nlmsghdr *) buf;
    
    while (NLMSG_OK(h, (__u32)status)) {
        if (h->nlmsg_type == NLMSG_DONE) {
            fastpath_log_debug( "NLMSG_DONE");
            goto rtn;
        }
        
        if (h->nlmsg_type == NLMSG_ERROR) { 
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                fprintf(stderr, "ERROR truncated\n");
            } else {
                errno = -err->error;
                perror("RTNETLINK answers");
            }
                
            goto rtn;
        }

        if (neigh_dispatch(h) != 0) {
            fastpath_log_error( "unhandled nlmsg_type %u", h->nlmsg_type);
        }
        
        h = NLMSG_NEXT(h, status);
    }

rtn:
    thread_add_read(mgr_master, neigh_socket_receive, mgr_master, THREAD_FD(thread));
    
    return 0;
}

static int neigh_socket_init(void)
{
    int rtnl_fd;
    struct sockaddr_nl rtnl_local;
    socklen_t addrlen;
    
    rtnl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rtnl_fd < 0) {
        fastpath_log_error( "%s: unable to create rtnetlink socket\n", __func__);
        return -1;
    }

    addrlen = sizeof(rtnl_local);

    memset(&rtnl_local, 0, sizeof(rtnl_local));
    rtnl_local.nl_family = AF_NETLINK;
    rtnl_local.nl_groups = RTMGRP_NEIGH;
    
    if (bind(rtnl_fd, (struct sockaddr *) &rtnl_local, addrlen) < 0) {
        fastpath_log_error( "%s: unable to bind rtnetlink socket\n", __func__);
        goto err_close;
    }

    if (getsockname(rtnl_fd, (struct sockaddr *)&rtnl_local, &addrlen) < 0) {
        fastpath_log_error( "%s: cannot gescockname(rtnl_socket)", __func__);
        goto err_close;
    }

    if (addrlen != sizeof(rtnl_local)) {
        fastpath_log_error( "%s: invalid address size %u", __func__, addrlen);
        goto err_close;
    }

    if (rtnl_local.nl_family != AF_NETLINK) {
        fastpath_log_error( "%s: invalid AF %u", __func__, rtnl_local.nl_family);
        goto err_close;
    }

    return rtnl_fd;

err_close:
    close(rtnl_fd);

    return -EIO;
}

int neigh_thread_add(void)
{
    struct thread *thread = NULL;
   
    neigh_sockfd = neigh_socket_init();
    if (neigh_sockfd < 0) {
        fastpath_log_error( "[%s]: create socket error ret(%s)\n", __func__, neigh_sockfd);
        return -EIO;
    }

    thread = thread_add_read(mgr_master, neigh_socket_receive, mgr_master, neigh_sockfd);
    if (thread == NULL) {
        fastpath_log_error( "[%s]: create domain socket thread error\n", __func__);
        return -EIO;
    }

    return 0;
}

static int manager_socket_receive(struct thread *thread)
{
    int length, ret;
    char req[FASTPATH_MSG_LENGTH] = {0};
    char resp[FASTPATH_MSG_LENGTH];
    struct sockaddr_in addr;
    struct msghdr msgh;
    struct iovec  iov;
    struct msg_hdr *msg;
    struct module *module;
    
    memset(req, 0, sizeof(req));
    memset(resp, 0, sizeof(resp));

    iov.iov_base = req;
    iov.iov_len = FASTPATH_MSG_LENGTH;

    msgh.msg_name = &addr;
    msgh.msg_namelen = sizeof(struct sockaddr_in);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    
    length = recvmsg(THREAD_FD(thread), &msgh, 0);
    if ((length < 0) || (length > FASTPATH_MSG_LENGTH)) {
        fastpath_log_error("[%s]: recv packet error, %m\n", __func__);
        goto rtn;
    }

    msg = (struct msg_hdr *)req;
    module = module_get_by_name((const char *)msg->path);
    if (module == NULL) {
        fastpath_log_error("invalid message, path %s\n", msg->path);
        goto rtn;
    }

    strncpy(resp, msg->path, sizeof(msg->path));
    ret = module->message(module, (struct msg_hdr *)req, (struct msg_hdr *)resp);
    
    iov.iov_base = resp;
    iov.iov_len = length;

    msgh.msg_name = &addr;
    msgh.msg_namelen = sizeof(struct sockaddr_in);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    
    length = sendmsg(THREAD_FD(thread), &msgh, 0);
    if (length < 0) {
        fastpath_log_error("[%s]: send to "NIPQUAD_FMT" failed\n", 
            __func__, NIPQUAD(addr.sin_addr.s_addr));
        goto rtn;
    }

rtn:
    thread = thread_add_read(mgr_master, manager_socket_receive, mgr_master, mgr_sockfd);
    if (thread == NULL) {
        fastpath_log_error("add mgr thread error\n");
        return -EPERM;
    }

    return 0;
}

static int manager_socket_init(void)
{
    int sd, flag, length, ret;
    struct sockaddr_in addr;
    
    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sd < 0) {
        return -1;
    }

    flag = fcntl(sd, F_GETFL, 0);
    ret = fcntl(sd, F_SETFL, flag | O_NONBLOCK);
    if (ret < 0) {
        return -1;
    }

    bzero(&addr, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4567);
    addr.sin_addr.s_addr = INADDR_ANY;
    length = sizeof(struct sockaddr_in);
    ret = bind(sd, (struct sockaddr *)&addr, (socklen_t)length);
    if (ret < 0) {
        return -1;
    }

    return sd;
}

int manager_thread_add(void)
{
    struct thread *thread = NULL;
   
    mgr_sockfd = manager_socket_init();
    if (mgr_sockfd < 0) {
        rte_exit(EXIT_FAILURE, "manager_thread_add: init socket failed\n");
    }
    
    thread = thread_add_read(mgr_master, manager_socket_receive, mgr_master, mgr_sockfd);
    if (thread == NULL) {
        fastpath_log_error("manager_thread_add: add thread error\n");
        return -EPERM;
    }

    return 0;
}


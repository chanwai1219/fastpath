#if 1

#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

static int conn_sockfd;

enum {
    NAT_INVALID = 0,
    NAT_SLOW,
    NAT_ORIG_SRC,
    NAT_ORIG_DST,
    NAT_REPL_SRC,
    NAT_REPL_DST,
    NAT_ORIG_SRC_CLOSE,
    NAT_ORIG_DST_CLOSE,
    NAT_REPL_SRC_CLOSE,
    NAT_REPL_DST_CLOSE,
};

typedef struct {
    uint32_t saddr;
    uint32_t daddr;
    uint32_t naddr;
    uint16_t sport;
    uint16_t dport;
    uint16_t nport;
    uint8_t proto;
    uint8_t type;
} conn_attr_t;

typedef struct {
    conn_attr_t orig;
    conn_attr_t repl;
} conn_info_t;

static inline int test_bit(int nr, const u_int32_t *addr)
{
    return ((1UL << (nr & 31)) & (addr[nr >> 5])) != 0;
}

static int nfattr_parse(struct nfattr *tb[], int max, struct nfattr *nfa, int len)
{
    memset(tb, 0, sizeof(struct nfattr *) * max);

    while (NFA_OK(nfa, len)) {
        if (NFA_TYPE(nfa) <= max)
            tb[NFA_TYPE(nfa)-1] = nfa;
                nfa = NFA_NEXT(nfa,len);
    }

    return len;
}

static int conn_send(void *conn)
{
    RTE_SET_USED(conn);
    return 0;
}

static int conn_process(struct nlmsghdr *nlh, struct nfattr *nfa[], struct nf_conntrack *ct)
{
    uint32_t type, snat = 0, dnat = 0;
    conn_info_t conn;
    struct __nfct_tuple *otuple, *rtuple;

    otuple = &ct->tuple[__DIR_ORIG];
	rtuple = &ct->tuple[__DIR_REPL];

    if (otuple->l3protonum != AF_INET) {
        fastpath_log_error("%s: rcv non inet msg, type %d\n", __func__, otuple->l3protonum);
        return -1;
    }

    if (otuple->protonum != IPPROTO_UDP && otuple->protonum != IPPROTO_TCP) {
#if 0
        fastpath_log_debug("%s: rcv non tcp/udp msg, protocol %d\n", __func__, otuple->protonum);
#endif
        return 0;
    }

    if (test_bit(ATTR_HELPER_NAME, ct->set)) {
        fastpath_log_debug("%s: rcv msg with helper name, ignore\n", __func__);
        return 0;
    }

    if (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
        snat = 1;
    } else if (nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT)){
        snat = 2;
    } else if (nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)){
        dnat = 1;
    } else if (nfct_getobjopt(ct, NFCT_GOPT_IS_DPAT)){
        dnat = 2;
    } else {
#if 0
        fastpath_log_debug("%s: rcv non nat conntrack msg, ignore\n", __func__);
#endif
        return 0;
    }

    conn.orig.saddr = ntohl(otuple->src.v4);    
    conn.orig.daddr = ntohl(otuple->dst.v4);    
    conn.orig.sport = ntohs(otuple->l4src.all);    
    conn.orig.dport = ntohs(otuple->l4dst.all);    
    conn.orig.proto = otuple->protonum;    

    conn.repl.saddr = ntohl(rtuple->src.v4);    
    conn.repl.daddr = ntohl(rtuple->dst.v4);    
    conn.repl.sport = ntohs(rtuple->l4src.all);    
    conn.repl.dport = ntohs(rtuple->l4dst.all);    
    conn.repl.proto = rtuple->protonum;    

    switch (NFNL_MSG_TYPE(nlh->nlmsg_type)) {
    case IPCTNL_MSG_CT_NEW:
        if (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)) {
            /* new */
            type = 0;
        } else {
            /* update */
            type = 1;
        }
        break;
    case IPCTNL_MSG_CT_DELETE:
        /* destroy */
        type = 3;
        break;
    }

    fastpath_log_debug("protocol %d snat %d dnat %d type %d status 0x%x state %d\n",
        otuple->protonum, snat, dnat, type, ct->status, ct->protoinfo.tcp.state);

    if (type == 1) {
        if (((IPPROTO_UDP == otuple->protonum) && (ct->status & IPS_ASSURED)) 
            || ((IPPROTO_TCP == otuple->protonum) && (TCP_CONNTRACK_ESTABLISHED == ct->protoinfo.tcp.state))) {
            if (snat) {
                conn.orig.naddr = ntohl(rtuple->dst.v4);
                conn.orig.nport = ntohs(rtuple->l4dst.all);
                conn.orig.type = NAT_ORIG_SRC;
                conn.repl.naddr = ntohl(otuple->src.v4);
                conn.repl.nport = ntohs(otuple->l4src.all);
                conn.repl.type = NAT_REPL_DST;
            } else {
                conn.orig.naddr = ntohl(rtuple->src.v4);
                conn.orig.nport = ntohs(rtuple->l4src.all);
                conn.orig.type = NAT_ORIG_DST;
                conn.repl.naddr = ntohl(otuple->dst.v4);
                conn.repl.nport = ntohs(otuple->l4dst.all);
                conn.repl.type = NAT_REPL_SRC;
            }

            conn.oper = NAT_SESSION_ADD;

            fastpath_log_debug("new nat session %d %d, "NIPQUAD_FMT":%d ==> "NIPQUAD_FMT":%d, "NIPQUAD_FMT":%d ==> "NIPQUAD_FMT":%d\n",
                    conn.orig.proto, conn.repl.proto, 
                    NIPQUAD(&conn.orig.saddr), conn.orig.sport, NIPQUAD(&conn.orig.daddr), conn.orig.dport,
                    NIPQUAD(&conn.repl.saddr), conn.repl.sport, NIPQUAD(&conn.repl.daddr), conn.repl.dport);

            if (conn_send(&conn) != 0) {
                return -1;
            }
        }
    } else if (type == 3) {
        if (0 == ct->status) {
            conn.oper = NAT_SESSION_DEL;
            conn.orig.type = NAT_INVALID;
            conn.repl.type = NAT_INVALID;

            fastpath_log_debug("del nat session %d %d, "NIPQUAD_FMT":%d ==> "NIPQUAD_FMT":%d, "NIPQUAD_FMT":%d ==> "NIPQUAD_FMT":%d\n",
                    conn.orig.proto, conn.repl.proto, 
                    NIPQUAD(&conn.orig.saddr), conn.orig.sport, NIPQUAD(&conn.orig.daddr), conn.orig.dport,
                    NIPQUAD(&conn.repl.saddr), conn.repl.sport, NIPQUAD(&conn.repl.daddr), conn.repl.dport);

            if (conn_send(&conn) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int conn_step(struct nlmsghdr *nlh)
{
    int err;
    int len;
    u_int8_t subsys;
    struct nfgenmsg *nfmsg;
    struct nfattr *attr;
    struct nfattr *tb[CTA_MAX+1];
    struct nf_conntrack ct;

    subsys = NFNL_SUBSYS_ID(nlh->nlmsg_type);
    if (subsys != NFNL_SUBSYS_CTNETLINK) {
        fastpath_log_debug("%s: recv subsys %d msg, nlmsg type %d, ignore\n", 
            __func__, subsys, nlh->nlmsg_type);
        return -1;
    }

    if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct nfgenmsg))) {
        fastpath_log_error("%s: recv wrong %d msg, length %d\n", __func__, nlh->nlmsg_len);
        return -1;
    }

    nfmsg = NLMSG_DATA(nlh);
    attr = NFM_NFA(nfmsg);
    len = nlh->nlmsg_len - NLMSG_ALIGN(NLMSG_SPACE(sizeof(struct nfgenmsg)));
    
    err = nfattr_parse(tb, CTA_MAX, attr, len);
    if (err == -1) {
        fastpath_log_error("%s: parse nfattr error\n", __func__);
        return -1;
    }

    memset(&ct, 0, sizeof(struct nf_conntrack));
    __parse_conntrack(nlh, tb, &ct);

    err = conn_process(nlh, tb, &ct);
    
    return err;
}

static int conn_socket_receive(struct thread *thread)
{
    socklen_t addrlen;
    int status;
    char buf[8192] = {0};
    struct sockaddr_nl peer;
    struct nlmsghdr *nlh;
    
    addrlen = sizeof(peer);
    status = recvfrom(THREAD_FD(thread), buf, 8192, 0, (struct sockaddr *)&peer, &addrlen);
    if (status < 0) {
        fastpath_log_error("OVERRUN on rtnl socket\n");
        goto rtn;
    }
    if (status == 0) {
        fastpath_log_error("EOF on rtnl socket\n");
        goto rtn;
    }
    if (addrlen != sizeof(peer)) {
        fastpath_log_error("invalid address size\n");
        goto rtn;
    }
    if (peer.nl_pid != 0) {
        fastpath_log_error("No message of desired type\n");
        goto rtn;
    }

    nlh = (struct nlmsghdr *)buf;

    while (status >= NLMSG_SPACE(0) && NLMSG_OK(nlh, status)) {
        if (nlh->nlmsg_type == NLMSG_ERROR ||
            (nlh->nlmsg_type == NLMSG_DONE && nlh->nlmsg_flags & NLM_F_MULTI)) {
            fastpath_log_debug("NLMSG_ERROR || NLM_F_MULTI\n");
            goto rtn;
        }

        if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct nfgenmsg))) {
            fastpath_log_debug("NLMSG LENGTH ERROR\n");
            goto rtn;
        }

        if (conn_step(nlh) != 0) {
            fastpath_log_error("%s: unhandled nlmsg_type %u", __func__, nlh->nlmsg_type);
        }
        
        nlh = NLMSG_NEXT(nlh, status);
    }
    
rtn:
    thread_add_read(mgr_master, conn_socket_receive, mgr_master, conn_sockfd);
    
    return 0;
}

static int conn_socket_init(void)
{
    int rtnl_fd;
    struct sockaddr_nl rtnl_local;
    socklen_t addrlen;
    
    rtnl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (rtnl_fd < 0) {
        fastpath_log_error("%s: unable to create rtnetlink socket\n", __func__);
        return -EIO;
    }

    addrlen = sizeof(rtnl_local);

    memset(&rtnl_local, 0, sizeof(rtnl_local));
    rtnl_local.nl_family = AF_NETLINK;
    rtnl_local.nl_groups = NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE | NF_NETLINK_CONNTRACK_DESTROY;

    if (bind(rtnl_fd, (struct sockaddr *) &rtnl_local, addrlen) < 0) {
        fastpath_log_error("%s: unable to bind rtnetlink socket\n", __func__);
        goto err_close;
    }

    if (getsockname(rtnl_fd, (struct sockaddr *)&rtnl_local, &addrlen) < 0) {
        fastpath_log_error("%s: cannot gescockname(rtnl_socket)", __func__);
        goto err_close;
    }

    if (addrlen != sizeof(rtnl_local)) {
        fastpath_log_error("%s: invalid address size %u", __func__, addrlen);
        goto err_close;
    }

    if (rtnl_local.nl_family != AF_NETLINK) {
        fastpath_log_error("%s: invalid AF %u", __func__, rtnl_local.nl_family);
        goto err_close;
    }

    return rtnl_fd;

err_close:
    close(rtnl_fd);

    return -EIO;
}

int conn_thread_add(void)
{
    struct thread *thread = NULL;
   
    conn_sockfd = conn_socket_init();
    if (conn_sockfd < 0) {
        fastpath_log_error("[%s]: create socket error ret(%s)\n", __func__, conn_sockfd);
        return -EIO;
    }

    thread = thread_add_read(mgr_master, conn_socket_receive, mgr_master, conn_sockfd);
    if (thread == NULL) {
        fastpath_log_error("[%s]: create domain socket thread error\n", __func__);
        return -EIO;
    }

    return 0;
}
#endif
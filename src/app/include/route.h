
#ifndef __ROUTE_H__
#define __ROUTE_H__

#define ROUTE_MAX_LINK  16

enum {
    ROUTE_MSG_ADD_NEIGH,
    ROUTE_MSG_DEL_NEIGH,
    ROUTE_MSG_ADD_NH,
    ROUTE_MSG_DEL_NH,
    ROUTE_MSG_ADD_NH6,
    ROUTE_MSG_DEL_NH6,
};

#define NEIGH_TYPE_LOCAL        1
#define NEIGH_TYPE_REACHABLE    2
#define NEIGH_TYPE_UNRESOLVED   3

struct arp_add {
    uint32_t nh_ip;
    uint32_t nh_iface;
    uint16_t type;
    struct ether_addr nh_arp;
};

struct arp_del {
    uint32_t nh_ip;
    uint32_t nh_iface;
};

struct route_add {
    uint32_t ip;
    uint8_t depth;
    uint32_t nh_ip;
    uint32_t nh_iface;
};

struct route_del {
    uint32_t ip;
    uint8_t depth;
};

struct route6_add {
    uint8_t ip[16];
    uint8_t depth;
    uint8_t nh_ip[16];
    uint32_t nh_iface;
};

struct route6_del {
    uint8_t ip[16];
    uint8_t depth;
};

void route_receive(struct rte_mbuf *m, struct module *peer, struct module *ipfwd);
void route_xmit(struct rte_mbuf *m, struct module *peer, struct module *ipfwd);
int route_connect(struct module *local, struct module *peer, void *param);
int route_handle_msg(struct module *route, 
    struct msg_hdr *req, struct msg_hdr *resp);
struct module * route_init(void);

#endif



#ifndef __ACL_H__
#define __ACL_H__

enum {
    ACL_MSG_ADD_IPV4_RULE,
    ACL_MSG_DEL_IPV4_RULE,
    ACL_MSG_ADD_IPV6_RULE,
    ACL_MSG_DEL_IPV6_RULE,
};

enum {
    ACL_ACTION_ACCEPT,
    ACL_ACTION_DENY,
};

struct acl_rule {
    uint8_t action;
    uint8_t proto;
    uint32_t saddr;
    uint32_t smask;
    uint32_t daddr;
    uint32_t dmask;
    uint16_t sport_low;
    uint16_t sport_high;
    uint16_t dport_low;
    uint16_t dport_high;
};

struct acl_rule6 {
    uint8_t action;
    uint8_t proto;
    uint32_t saddr[4];
    uint32_t smask;
    uint32_t daddr[4];
    uint32_t dmask;
    uint16_t sport_low;
    uint16_t sport_high;
    uint16_t dport_low;
    uint16_t dport_high;
};

void acl_receive(struct rte_mbuf *m, struct module *peer, struct module *acl);
void acl_xmit(struct rte_mbuf *m, struct module *peer, struct module *acl);
int acl_connect(struct module *local, struct module *peer, void *param);
int acl_handle_msg(struct module *acl, struct msg_hdr *req, struct msg_hdr *resp);
struct module * acl_init(uint16_t index);

#endif


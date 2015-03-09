
#include "include/fastpath.h"

#define uint32_t_to_char(ip, a, b, c, d) do {\
        *a = (unsigned char)(ip >> 24 & 0xff);\
        *b = (unsigned char)(ip >> 16 & 0xff);\
        *c = (unsigned char)(ip >> 8 & 0xff);\
        *d = (unsigned char)(ip & 0xff);\
    } while (0)

#define ACL_MAX_SIZE        0
#define ACL_MAX_RULES       32
#define ACL_BLD_CATEGORIES  1
#define ACL_CLASSIFY_ALG    RTE_ACL_CLASSIFY_DEFAULT

/*
 * Rule and trace formats definitions.
 */

struct ipv4_5tuple {
    uint8_t  proto;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
};

enum {
    PROTO_FIELD_IPV4,
    SRC_FIELD_IPV4,
    DST_FIELD_IPV4,
    SRCP_FIELD_IPV4,
    DSTP_FIELD_IPV4,
    NUM_FIELDS_IPV4
};

struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = PROTO_FIELD_IPV4,
        .input_index = RTE_ACL_IPV4VLAN_PROTO,
        .offset = offsetof(struct ipv4_5tuple, proto),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC_FIELD_IPV4,
        .input_index = RTE_ACL_IPV4VLAN_SRC,
        .offset = offsetof(struct ipv4_5tuple, ip_src),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST_FIELD_IPV4,
        .input_index = RTE_ACL_IPV4VLAN_DST,
        .offset = offsetof(struct ipv4_5tuple, ip_dst),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = SRCP_FIELD_IPV4,
        .input_index = RTE_ACL_IPV4VLAN_PORTS,
        .offset = offsetof(struct ipv4_5tuple, port_src),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = DSTP_FIELD_IPV4,
        .input_index = RTE_ACL_IPV4VLAN_PORTS,
        .offset = offsetof(struct ipv4_5tuple, port_dst),
    },
};

#define IPV6_ADDR_LEN    16
#define IPV6_ADDR_U16    (IPV6_ADDR_LEN / sizeof(uint16_t))
#define IPV6_ADDR_U32    (IPV6_ADDR_LEN / sizeof(uint32_t))

struct ipv6_5tuple {
    uint8_t  proto;
    uint32_t ip_src[IPV6_ADDR_U32];
    uint32_t ip_dst[IPV6_ADDR_U32];
    uint16_t port_src;
    uint16_t port_dst;
};

enum {
    PROTO_FIELD_IPV6,
    SRC1_FIELD_IPV6,
    SRC2_FIELD_IPV6,
    SRC3_FIELD_IPV6,
    SRC4_FIELD_IPV6,
    DST1_FIELD_IPV6,
    DST2_FIELD_IPV6,
    DST3_FIELD_IPV6,
    DST4_FIELD_IPV6,
    SRCP_FIELD_IPV6,
    DSTP_FIELD_IPV6,
    NUM_FIELDS_IPV6
};

struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = PROTO_FIELD_IPV6,
        .input_index = PROTO_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, proto),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC1_FIELD_IPV6,
        .input_index = SRC1_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, ip_src[0]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC2_FIELD_IPV6,
        .input_index = SRC2_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, ip_src[1]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC3_FIELD_IPV6,
        .input_index = SRC3_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, ip_src[2]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC4_FIELD_IPV6,
        .input_index = SRC4_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, ip_src[3]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST1_FIELD_IPV6,
        .input_index = DST1_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, ip_dst[0]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST2_FIELD_IPV6,
        .input_index = DST2_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, ip_dst[1]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST3_FIELD_IPV6,
        .input_index = DST3_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, ip_dst[2]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST4_FIELD_IPV6,
        .input_index = DST4_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, ip_dst[3]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = SRCP_FIELD_IPV6,
        .input_index = SRCP_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, port_src),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = DSTP_FIELD_IPV6,
        .input_index = SRCP_FIELD_IPV6,
        .offset = offsetof(struct ipv6_5tuple, port_dst),
    },
};


enum {
    CB_FLD_SRC_ADDR,
    CB_FLD_DST_ADDR,
    CB_FLD_SRC_PORT_LOW,
    CB_FLD_SRC_PORT_DLM,
    CB_FLD_SRC_PORT_HIGH,
    CB_FLD_DST_PORT_LOW,
    CB_FLD_DST_PORT_DLM,
    CB_FLD_DST_PORT_HIGH,
    CB_FLD_PROTO,
    CB_FLD_NUM,
};

enum {
    CB_TRC_SRC_ADDR,
    CB_TRC_DST_ADDR,
    CB_TRC_SRC_PORT,
    CB_TRC_DST_PORT,
    CB_TRC_PROTO,
    CB_TRC_NUM,
};

struct acl_private {
    uint32_t ipv4_rules;
    uint32_t ipv6_rules;
    struct rte_acl_ctx *acx;
    struct rte_acl_ctx *acx6;
    struct module *lower;
    struct module *upper;
};

static uint32_t ipv4_priority;
static uint32_t ipv6_priority;

static inline void
print_one_ipv4_rule(struct rte_acl_rule *rule, int extra)
{
    unsigned char a, b, c, d;

    uint32_t_to_char(rule->field[SRC_FIELD_IPV4].value.u32,
            &a, &b, &c, &d);
    fastpath_log_debug("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
            rule->field[SRC_FIELD_IPV4].mask_range.u32);
    uint32_t_to_char(rule->field[DST_FIELD_IPV4].value.u32,
            &a, &b, &c, &d);
    fastpath_log_debug("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
            rule->field[DST_FIELD_IPV4].mask_range.u32);
    fastpath_log_debug("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
        rule->field[SRCP_FIELD_IPV4].value.u16,
        rule->field[SRCP_FIELD_IPV4].mask_range.u16,
        rule->field[DSTP_FIELD_IPV4].value.u16,
        rule->field[DSTP_FIELD_IPV4].mask_range.u16,
        rule->field[PROTO_FIELD_IPV4].value.u8,
        rule->field[PROTO_FIELD_IPV4].mask_range.u8);
    if (extra)
        fastpath_log_debug("0x%x-0x%x-0x%x ",
            rule->data.category_mask,
            rule->data.priority,
            rule->data.userdata);
}

static inline void
print_one_ipv6_rule(struct rte_acl_rule *rule, int extra)
{
    unsigned char a, b, c, d;

    uint32_t_to_char(rule->field[SRC1_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    fastpath_log_debug("%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[SRC2_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    fastpath_log_debug(":%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[SRC3_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    fastpath_log_debug(":%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[SRC4_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    fastpath_log_debug(":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
            rule->field[SRC1_FIELD_IPV6].mask_range.u32
            + rule->field[SRC2_FIELD_IPV6].mask_range.u32
            + rule->field[SRC3_FIELD_IPV6].mask_range.u32
            + rule->field[SRC4_FIELD_IPV6].mask_range.u32);

    uint32_t_to_char(rule->field[DST1_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    fastpath_log_debug("%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[DST2_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    fastpath_log_debug(":%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[DST3_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    fastpath_log_debug(":%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[DST4_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    fastpath_log_debug(":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
            rule->field[DST1_FIELD_IPV6].mask_range.u32
            + rule->field[DST2_FIELD_IPV6].mask_range.u32
            + rule->field[DST3_FIELD_IPV6].mask_range.u32
            + rule->field[DST4_FIELD_IPV6].mask_range.u32);

    fastpath_log_debug("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
        rule->field[SRCP_FIELD_IPV6].value.u16,
        rule->field[SRCP_FIELD_IPV6].mask_range.u16,
        rule->field[DSTP_FIELD_IPV6].value.u16,
        rule->field[DSTP_FIELD_IPV6].mask_range.u16,
        rule->field[PROTO_FIELD_IPV6].value.u8,
        rule->field[PROTO_FIELD_IPV6].mask_range.u8);
    if (extra)
        fastpath_log_debug("0x%x-0x%x-0x%x ",
            rule->data.category_mask,
            rule->data.priority,
            rule->data.userdata);
}

static int acl_add_ipv4_rule(struct rte_acl_ctx *ctx, struct acl_rule *rule)
{
    struct rte_acl_rule acl_rule;

    acl_rule.field[SRC_FIELD_IPV4].value.u32 = rte_be_to_cpu_32(rule->saddr);
    acl_rule.field[SRC_FIELD_IPV4].mask_range.u32 = rte_be_to_cpu_32(rule->smask);
    
    acl_rule.field[DST_FIELD_IPV4].value.u32 = rte_be_to_cpu_32(rule->daddr);
    acl_rule.field[DST_FIELD_IPV4].mask_range.u32 = rte_be_to_cpu_32(rule->dmask);
    
    acl_rule.field[SRCP_FIELD_IPV4].value.u16 = rte_be_to_cpu_16(rule->sport_low);
    acl_rule.field[SRCP_FIELD_IPV4].mask_range.u16 = rte_be_to_cpu_16(rule->sport_high);

    acl_rule.field[DSTP_FIELD_IPV4].value.u16 = rte_be_to_cpu_16(rule->dport_low);
    acl_rule.field[DSTP_FIELD_IPV4].mask_range.u16 = rte_be_to_cpu_16(rule->dport_high);

    acl_rule.field[PROTO_FIELD_IPV4].value.u8 = rule->proto;
    acl_rule.field[PROTO_FIELD_IPV4].mask_range.u8 = 0xFF;
    
    acl_rule.data.category_mask = LEN2MASK(RTE_ACL_MAX_CATEGORIES);
    acl_rule.data.priority = ipv4_priority--;
    acl_rule.data.userdata = rule->action;

    print_one_ipv4_rule(&acl_rule, 1);

    return rte_acl_add_rules(ctx, &acl_rule, 1);
}

static int acl_del_ipv4_rule(struct rte_acl_ctx *ctx, struct acl_rule *rule)
{
    RTE_SET_USED(ctx);
    RTE_SET_USED(rule);
    return 0;
}

static int acl_add_ipv6_rule(struct rte_acl_ctx *ctx, struct acl_rule6 *rule)
{
    uint32_t i;
    struct rte_acl_rule acl_rule;
    const uint32_t nbu32 = sizeof(uint32_t) * CHAR_BIT;

    for (i = 0; i < RTE_DIM(rule->saddr); i++) {
        acl_rule.field[SRC1_FIELD_IPV6 + i].value.u32 = rule->saddr[i];
        if (rule->smask >= (i + 1) * nbu32) {
            acl_rule.field[SRC1_FIELD_IPV6 + i].mask_range.u32 = nbu32;
        } else {
            acl_rule.field[SRC1_FIELD_IPV6 + i].mask_range.u32 = 
                rule->smask > (i * nbu32) ? rule->smask - (i * 32) : 0;
        }
    }

    for (i = 0; i < RTE_DIM(rule->daddr); i++) {
        acl_rule.field[DST1_FIELD_IPV6 + i].value.u32 = rule->daddr[i];
        if (rule->dmask >= (i + 1) * nbu32) {
            acl_rule.field[DST1_FIELD_IPV6 + i].mask_range.u32 = nbu32;
        } else {
            acl_rule.field[DST1_FIELD_IPV6 + i].mask_range.u32 = 
                rule->dmask > (i * nbu32) ? rule->dmask - (i * 32) : 0;
        }
    }

    acl_rule.field[SRCP_FIELD_IPV6].value.u16 = rte_be_to_cpu_16(rule->sport_low);
    acl_rule.field[SRCP_FIELD_IPV6].mask_range.u16 = rte_be_to_cpu_16(rule->sport_high);

    acl_rule.field[DSTP_FIELD_IPV6].value.u16 = rte_be_to_cpu_16(rule->dport_low);
    acl_rule.field[DSTP_FIELD_IPV6].mask_range.u16 = rte_be_to_cpu_16(rule->dport_high);

    acl_rule.field[PROTO_FIELD_IPV6].value.u8 = rule->proto;
    acl_rule.field[PROTO_FIELD_IPV6].mask_range.u8 = 0xFF;

    acl_rule.data.category_mask = LEN2MASK(RTE_ACL_MAX_CATEGORIES);
    acl_rule.data.priority = ipv6_priority--;
    acl_rule.data.userdata = rule->action;

    print_one_ipv6_rule(&acl_rule, 1);

    return rte_acl_add_rules(ctx, &acl_rule, 1);
}

static int acl_del_ipv6_rule(struct rte_acl_ctx *ctx, struct acl_rule6 *rule)
{
    RTE_SET_USED(ctx);
    RTE_SET_USED(rule);
    return 0;
}

void acl_receive(struct rte_mbuf *m, struct module *peer, struct module *acl)
{
    struct acl_private *private = (struct acl_private *)acl->private;
    
    RTE_SET_USED(peer);

    SEND_PKT(m, acl, private->upper, PKT_DIR_RECV);
}

void acl_xmit(struct rte_mbuf *m, struct module *peer, struct module *acl)
{
    struct acl_private *private = (struct acl_private *)acl->private;

    RTE_SET_USED(peer);
    
    SEND_PKT(m, acl, private->lower, PKT_DIR_XMIT);
}

int acl_connect(struct module *local, struct module *peer, void *param)
{
    struct acl_private *private;

    RTE_SET_USED(param);
    
    if (local == NULL || peer == NULL) {
        fastpath_log_error("acl_connect: invalid local %p peer %p\n", 
            local, peer);
        return -EINVAL;
    }

    fastpath_log_info("acl_connect: local %s peer %s\n", local->name, peer->name);

    private = (struct acl_private *)local->private;

    if (peer->type == MODULE_TYPE_INTERFACE) {
        private->lower = peer;
        
        peer->connect(peer, local, NULL);
    } else if (peer->type == MODULE_TYPE_ROUTE || peer->type == MODULE_TYPE_TCM) {
        private->upper = peer;
    } else {
        fastpath_log_error("acl_connect: invalid peer type %d\n", peer->type);
        return -ENOENT;
    }

    return 0;
}

int acl_handle_msg(struct module *acl, 
    struct msg_hdr *req, struct msg_hdr *resp)
{
    int ret;
    struct acl_private *private = acl->private;
    
    resp->cmd = req->cmd;

    fastpath_log_debug("acl_handle_msg: cmd %d\n", req->cmd);
    
    switch (req->cmd) {
    case ACL_MSG_ADD_IPV4_RULE:
        {
            struct acl_rule *rule = (struct acl_rule *)req->data;
            ret = acl_add_ipv4_rule(private->acx, rule);
            if (ret != 0) {
                fastpath_log_error("acl_add_ipv4_rule failed\n");
                resp->flag = FASTPATH_MSG_FAILED;
            }
        }
        break;
    case ACL_MSG_DEL_IPV4_RULE:
        {
            struct acl_rule *rule = (struct acl_rule *)req->data;
            ret = acl_del_ipv4_rule(private->acx, rule);
            if (ret != 0) {
                fastpath_log_error("acl_del_ipv4_rule failed\n");
                resp->flag = FASTPATH_MSG_FAILED;
            }
        }
        break;
    case ACL_MSG_ADD_IPV6_RULE:
        {
            struct acl_rule6 *rule = (struct acl_rule6 *)req->data;
            ret = acl_add_ipv6_rule(private->acx6, rule);
            if (ret != 0) {
                fastpath_log_error("acl_add_ipv6_rule failed\n");
                resp->flag = FASTPATH_MSG_FAILED;
            }
        }
        break;
    case ACL_MSG_DEL_IPV6_RULE:
        {
            struct acl_rule6 *rule = (struct acl_rule6 *)req->data;
            ret = acl_del_ipv6_rule(private->acx6, rule);
            if (ret != 0) {
                fastpath_log_error("acl_del_ipv6_rule failed\n");
                resp->flag = FASTPATH_MSG_FAILED;
            }
        }
        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

struct module* acl_init(uint16_t index)
{
    int ret;
    char name[32];
    struct rte_acl_param prm;
    struct rte_acl_config cfg;
    struct module *acl = NULL;
    struct acl_private *private = NULL;

    if (index >= ROUTE_MAX_LINK) {
        fastpath_log_error("acl_init: invalid index %d\n", index);
        return NULL;
    }

    ipv4_priority = RTE_ACL_MAX_PRIORITY;
    ipv6_priority = RTE_ACL_MAX_PRIORITY;

    memset(&cfg, 0, sizeof(struct rte_acl_config));

    acl = rte_zmalloc(NULL, sizeof(struct module), 0);
    if (acl == NULL) {
        fastpath_log_error("acl_init: malloc module failed\n");
        goto err_out;
    }

    acl->type = MODULE_TYPE_ACL;
    acl->receive = acl_receive;
    acl->transmit = acl_xmit;
    acl->connect = acl_connect;
    acl->message = acl_handle_msg;
    snprintf(acl->name, sizeof(acl->name), "acl%d", index);

    private = rte_zmalloc(NULL, sizeof(struct acl_private), 0);
    if (private == NULL) {      
        fastpath_log_error("acl_init: malloc acl_private failed\n");
        goto err_out;
    }

    /* setup ACL build config. */
    cfg.num_fields = RTE_DIM(ipv4_defs);
    memcpy(&cfg.defs, ipv4_defs, sizeof(ipv4_defs));
    cfg.num_categories = ACL_BLD_CATEGORIES;
    cfg.max_size = ACL_MAX_SIZE;

    /* setup ACL creation parameters. */
    snprintf(name, sizeof(name), "acl_ctx_%d_ipv4", index);
    prm.name = name;
    prm.socket_id = SOCKET_ID_ANY;
    prm.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));
    prm.max_rule_num = ACL_MAX_RULES;    

    private->acx = rte_acl_create(&prm);
    if (private->acx == NULL) {
        fastpath_log_error("acl_init: rte_acl_create failed\n");
        goto err_out;
    }

    ret = rte_acl_set_ctx_classify(private->acx, ACL_CLASSIFY_ALG);
    if (ret != 0) {
        fastpath_log_error("acl_init: rte_acl_set_ctx_classify failed\n");
        goto err_out;
    }

    ret = rte_acl_build(private->acx, &cfg);
    if (ret != 0) {
        fastpath_log_error("acl_init: rte_acl_build failed\n");
        goto err_out;
    }

    rte_acl_dump(private->acx);

    /* setup ACL build config. */
    cfg.num_fields = RTE_DIM(ipv6_defs);
    memcpy(&cfg.defs, ipv6_defs, sizeof(ipv6_defs));
    cfg.num_categories = ACL_BLD_CATEGORIES;
    cfg.max_size = ACL_MAX_SIZE;

    /* setup ACL creation parameters. */
    snprintf(name, sizeof(name), "acl_ctx_%d_ipv6", index);
    prm.name = name;
    prm.socket_id = SOCKET_ID_ANY;
    prm.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs));
    prm.max_rule_num = ACL_MAX_RULES;    

    private->acx6 = rte_acl_create(&prm);
    if (private->acx6 == NULL) {
        fastpath_log_error("acl_init: rte_acl_create ipv6 failed\n");
        goto err_out;
    }

    ret = rte_acl_set_ctx_classify(private->acx6, ACL_CLASSIFY_ALG);
    if (ret != 0) {
        fastpath_log_error("acl_init: rte_acl_set_ctx_classify ipv6 failed\n");
        goto err_out;
    }

    ret = rte_acl_build(private->acx6, &cfg);
    if (ret != 0) {
        fastpath_log_error("acl_init: rte_acl_build ipv6 failed\n");
        goto err_out;
    }

    rte_acl_dump(private->acx6);

    acl->private = private;

    return acl;
    
err_out:
    if (private) {
        if (private->acx)
            rte_acl_free(private->acx);
        if (private->acx6)
            rte_acl_free(private->acx6);
        
        rte_free(private);
    }
    
    if (acl)
        rte_free(acl);

    return NULL;
}


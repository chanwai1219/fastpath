
#include "fastpath.h"

#define NEIGH_TYPE_LOCAL        1
#define NEIGH_TYPE_REACHABLE    2
#define NEIGH_TYPE_UNRESOLVED   3

struct arp_entry {
    uint16_t type;
    struct ether_addr nh_arp;
};

struct lpm_key {
    uint32_t ip;
    uint8_t depth;
};

struct lpm6_key {
    uint8_t ip[16];
    uint8_t depth;
};

struct nh_entry {
    uint32_t nh_ip;
    uint32_t nh_iface;
};

struct nh6_entry {
    uint8_t  nh_ip[16];
    uint32_t nh_iface;
};

/* Next Hop Table (NHT) */
struct nh_table {
    uint32_t nht_users[FASTPATH_LPM_MAX_NEXT_HOPS];
    struct nh_entry nht[FASTPATH_LPM_MAX_NEXT_HOPS];
} __rte_cache_aligned;

struct nh6_table {
    uint32_t nht_users[FASTPATH_LPM_MAX_NEXT_HOPS];
    struct nh6_entry nht[FASTPATH_LPM_MAX_NEXT_HOPS];
} __rte_cache_aligned;

struct route_private {
    struct module *ipv4[ROUTE_MAX_LINK];
    struct module *ipv6[ROUTE_MAX_LINK];
    struct rte_lpm *lpm_tbl;
    struct rte_lpm6 *lpm6_tbl;
    struct nh_table *nh_tbl;
    struct nh6_table *nh6_tbl;
    struct nh_entry *default_nh;
    struct nh6_entry *default_nh6;
    struct rte_hash *neigh_hash_tbl;
    struct rte_hash *neigh_hash_tbl6;
    struct arp_entry *neigh_tbl;
} __rte_cache_aligned;

struct module *route_module;

static void neigh_init(struct module *route);
static void lpm_init(struct module *route);
static int neigh_add(struct module *route, struct nh_entry *nh, struct arp_entry *neigh);
static int neigh_del(struct module *route, struct nh_entry *nh);
static int nh_add(struct module *route, struct lpm_key *key, struct nh_entry *nh);
static int nh_del(struct module *route, struct lpm_key *key);
static int nh6_add(struct module *route, struct lpm6_key *key, struct nh6_entry *nh);
static int nh6_del(struct module *route, struct lpm6_key *key);

static int
nht_find_existing(struct nh_table *tbl, void *entry, uint32_t *pos)
{
    uint32_t i;

    for (i = 0; i < FASTPATH_LPM_MAX_NEXT_HOPS; i++) {
        if ((tbl->nht_users[i] > 0) && 
            (memcmp(&tbl->nht[i], entry, sizeof(struct nh_entry)) == 0)) {
            *pos = i;
            return 1;
        }
    }

    return 0;
}

static int
nht6_find_existing(struct nh6_table *tbl, void *entry, uint32_t *pos)
{
    uint32_t i;

    for (i = 0; i < FASTPATH_LPM_MAX_NEXT_HOPS; i++) {
        if ((tbl->nht_users[i] > 0) && 
            (memcmp(&tbl->nht[i], entry, sizeof(struct nh6_entry)) == 0)) {
            *pos = i;
            return 1;
        }
    }

    return 0;
}

static int
nht_find_free(struct nh_table *tbl, uint32_t *pos)
{
    uint32_t i;

    for (i = 0; i < FASTPATH_LPM_MAX_NEXT_HOPS; i++) {
        if (tbl->nht_users[i] == 0) {
            *pos = i;
            return 1;
        }
    }

    return 0;
}

static int
nht6_find_free(struct nh6_table *tbl, uint32_t *pos)
{
    uint32_t i;

    for (i = 0; i < FASTPATH_LPM_MAX_NEXT_HOPS; i++) {
        if (tbl->nht_users[i] == 0) {
            *pos = i;
            return 1;
        }
    }

    return 0;
}

int neigh_add(struct module *route, struct nh_entry *nh, struct arp_entry *neigh)
{
    int ret;
    
    struct route_private *private = (struct route_private *)route->private;

    ret = rte_hash_add_key(private->neigh_hash_tbl, (void *)nh);
    if (ret < 0) {
        fastpath_log_error("neigh_add: add "NIPQUAD_FMT" iface %d faild\n",
            HIPQUAD(nh->nh_ip), nh->nh_iface);
        return ret;
    }

    memcpy(&private->neigh_tbl[ret], neigh, sizeof(struct arp_entry));

    return 0;
}

int neigh_del(struct module *route, struct nh_entry *nh)
{
    int ret;
    
    struct route_private *private = (struct route_private *)route->private;

    ret = rte_hash_del_key(private->neigh_hash_tbl, (void *)nh);
    if (ret < 0) {
        fastpath_log_error("neigh_del: ip "NIPQUAD_FMT" iface %d not exist\n",
            HIPQUAD(nh->nh_ip), nh->nh_iface);
        return ret;
    }

    memset(&private->neigh_tbl[ret], 0, sizeof(struct arp_entry));

    return 0;
}

int nh_add(struct module *route, struct lpm_key *key, struct nh_entry *nh)
{
    int status;
    uint8_t nht_pos0 = 0;
    uint32_t nht_pos, nht_pos0_valid;
    struct route_private *private = (struct route_private *)route->private;

    if (key->depth > 32) {
        fastpath_log_error("nh_add: invalid depth (%d)\n", key->depth);
        return -EINVAL;
    }

    if (key->depth == 0) {
        private->default_nh->nh_ip = nh->nh_ip;
        private->default_nh->nh_iface = nh->nh_iface;
        return 0;
    }
    
    status = rte_lpm_is_rule_present(private->lpm_tbl, key->ip, key->depth, &nht_pos0);
    nht_pos0_valid = status > 0;

    if (nht_find_existing(private->nh_tbl, nh, &nht_pos) == 0) {
        if (nht_find_free(private->nh_tbl, &nht_pos) == 0) {
            fastpath_log_error("nh_add: NHT full\n");
            return -1;
        }

        memcpy(&private->nh_tbl[nht_pos], nh, sizeof(struct nh_entry));
    }

    /* Add rule to low level LPM table */
    if (rte_lpm_add(private->lpm_tbl, key->ip, key->depth, (uint8_t)nht_pos) < 0) {
        fastpath_log_error("nh_add: LPM rule add failed\n");
        return -1;
    }

    /* Commit NHT changes */
    private->nh_tbl->nht_users[nht_pos]++;
    private->nh_tbl->nht_users[nht_pos0] -= nht_pos0_valid;

    return 0;
}

int nh_del(struct module *route, struct lpm_key *key)
{
    int status;
    uint8_t nht_pos;
    struct route_private *private = (struct route_private *)route->private;
    
    if (key->depth > 32) {
        fastpath_log_error("nh_del: invalid depth (%d)\n", key->depth);
        return -EINVAL;
    }

    if (key->depth == 0) {
        memset(private->default_nh, 0, sizeof(struct nh_entry));
        return 0;
    }

    /* Return if rule is not present in the table */
    status = rte_lpm_is_rule_present(private->lpm_tbl, key->ip, key->depth, &nht_pos);
    if (status <= 0) {
        fastpath_log_error("nh_del: ip "NIPQUAD_FMT" depth %d\n", 
            HIPQUAD(key->ip), key->depth);
        return -ENOENT;
    }

    /* Delete rule from the low-level LPM table */
    status = rte_lpm_delete(private->lpm_tbl, key->ip, key->depth);
    if (status) {
        fastpath_log_error("nh_del: LPM rule delete failed\n");
        return -1;
    }

    /* Commit NHT changes */
    private->nh_tbl->nht_users[nht_pos]--;

    return 0;
}

int nh6_add(struct module *route, struct lpm6_key *key, struct nh6_entry *nh)
{
    int status;
    uint8_t nht_pos0 = 0;
    uint32_t nht_pos, nht_pos0_valid;
    struct route_private *private = (struct route_private *)route->private;

    if (key->depth == 0 || key->depth > 128) {
        fastpath_log_error("nh_add: invalid depth (%d)\n", key->depth);
        return -EINVAL;
    }
    
    status = rte_lpm6_is_rule_present(private->lpm6_tbl, key->ip, key->depth, &nht_pos0);
    nht_pos0_valid = status > 0;

    if (nht6_find_existing(private->nh6_tbl, nh, &nht_pos) == 0) {
        if (nht6_find_free(private->nh6_tbl, &nht_pos) == 0) {
            fastpath_log_error("nh6_add: NHT full\n");
            return -1;
        }

        memcpy(&private->nh6_tbl[nht_pos], nh, sizeof(struct nh6_entry));
    }

    /* Add rule to low level LPM table */
    if (rte_lpm6_add(private->lpm6_tbl, key->ip, key->depth, (uint8_t)nht_pos) < 0) {
        fastpath_log_error("nh6_add: LPM6 rule add failed\n");
        return -1;
    }

    /* Commit NHT changes */
    private->nh6_tbl->nht_users[nht_pos]++;
    private->nh6_tbl->nht_users[nht_pos0] -= nht_pos0_valid;

    return 0;
}

int nh6_del(struct module *route, struct lpm6_key *key)
{
    int status;
    uint8_t nht_pos;
    struct route_private *private = (struct route_private *)route->private;
    
    if (key->depth == 0 || key->depth > 128) {
        fastpath_log_error("nh6_del: invalid depth (%d)\n", key->depth);
        return -EINVAL;
    }

    /* Return if rule is not present in the table */
    status = rte_lpm6_is_rule_present(private->lpm6_tbl, key->ip, key->depth, &nht_pos);
    if (status <= 0) {
        fastpath_log_error("nh6_del: ip "NIP6_FMT" depth %d\n", 
            NIP6(key->ip), key->depth);
        return -ENOENT;
    }

    /* Delete rule from the low-level LPM table */
    status = rte_lpm6_delete(private->lpm6_tbl, key->ip, key->depth);
    if (status) {
        fastpath_log_error("nh6_del: LPM6 rule delete failed\n");
        return -1;
    }

    /* Commit NHT changes */
    private->nh6_tbl->nht_users[nht_pos]--;

    return 0;
}

void route_receive(struct rte_mbuf *m, 
    __rte_unused struct module *peer, struct module *route)
{
    uint8_t next_hop;
    int neigh_idx;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct ipv6_hdr *ipv6_hdr;
    struct nh_entry *nh;
    struct nh6_entry *nh6;
    struct arp_entry *neigh;
    struct route_private *private = (struct route_private *)route->private;
    struct fastpath_pkt_metadata *c =
        (struct fastpath_pkt_metadata *)RTE_MBUF_METADATA_UINT8_PTR(m, 0);
    
    if (c->protocol == ETHER_TYPE_IPv4) {
        ipv4_hdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);

        fastpath_log_debug("route receive pkt "NIPQUAD_FMT" ==> "NIPQUAD_FMT"\n",
            NIPQUAD(ipv4_hdr->src_addr), NIPQUAD(ipv4_hdr->dst_addr));
        
        /* Find destination port */
        if (rte_lpm_lookup(private->lpm_tbl, 
            rte_be_to_cpu_32(ipv4_hdr->dst_addr), &next_hop) == 0) {
            nh = &private->nh_tbl->nht[next_hop];
        } else {
            nh = private->default_nh;
        }
        if (nh == NULL || nh->nh_ip == 0) {
            fastpath_log_debug("lpm entry for "NIPQUAD_FMT" not found, drop packet\n",
                NIPQUAD(ipv4_hdr->dst_addr));
            rte_pktmbuf_free(m);
            return;
        }

        neigh_idx = rte_hash_lookup(private->neigh_hash_tbl, (void *)nh);
        if (neigh_idx < 0) {
            fastpath_log_debug("neigh entry for "NIPQUAD_FMT"@%d not found, drop packet\n",
                HIPQUAD(nh->nh_ip), nh->nh_iface);
            rte_pktmbuf_free(m);
            return;
        }
        
        neigh = &private->neigh_tbl[neigh_idx];

        fastpath_log_debug("route found "NIPQUAD_FMT" next hop "MAC_FMT" type %d\n",
            NIPQUAD(ipv4_hdr->dst_addr), MAC_ARG(&neigh->nh_arp), neigh->type);
        
        switch (neigh->type) {
        case NEIGH_TYPE_LOCAL:
            fastpath_log_debug("route receive proto %d packet, will be supported later\n",
                ipv4_hdr->next_proto_id);
            rte_pktmbuf_free(m);
            break;

        case NEIGH_TYPE_REACHABLE:
            c->mac_header = rte_pktmbuf_mtod(m, uint8_t *) - sizeof(struct ether_hdr);
            eth_hdr = (struct ether_hdr *)c->mac_header;
            rte_memcpy(&eth_hdr->d_addr, &neigh->nh_arp, sizeof(struct ether_hdr));
            eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
            SEND_PKT(m, route, private->ipv4[nh->nh_iface], PKT_DIR_XMIT);
            break;

        default:
            rte_pktmbuf_free(m);
            break;
        }
    } else if (c->protocol == ETHER_TYPE_IPv6) {
        ipv6_hdr = rte_pktmbuf_mtod(m, struct ipv6_hdr *);

        /* Find destination port */
        if (rte_lpm6_lookup(private->lpm6_tbl, ipv6_hdr->dst_addr, &next_hop) == 0) {
            nh6 = &private->nh6_tbl->nht[next_hop];
        } else {
            nh6 = private->default_nh6;
        }

        if (nh6 == NULL) {
            fastpath_log_debug("lpm6 entry for "NIP6_FMT" not found, drop packet\n",
                NIP6(ipv6_hdr->dst_addr));
            rte_pktmbuf_free(m);
            return;
        }

        neigh_idx = rte_hash_lookup(private->neigh_hash_tbl6, (void *)nh6);
        if (neigh_idx < 0) {
            fastpath_log_debug("neigh entry for "NIP6_FMT" not found, drop packet\n",
                NIP6(ipv6_hdr->dst_addr));
            rte_pktmbuf_free(m);
            return;
        }

        neigh = &private->neigh_tbl[neigh_idx];
        switch (neigh->type) {
        case NEIGH_TYPE_LOCAL:
            fastpath_log_debug("route receive proto %d packet, will be supported later\n",
                ipv6_hdr->proto);
            rte_pktmbuf_free(m);
            break;

        case NEIGH_TYPE_REACHABLE:
            c->mac_header = rte_pktmbuf_mtod(m, uint8_t *) - sizeof(struct ether_hdr);
            rte_memcpy(c->mac_header, &neigh->nh_arp, sizeof(struct ether_hdr));
            SEND_PKT(m, route, private->ipv6[nh6->nh_iface], PKT_DIR_XMIT);
            break;

        default:
            rte_pktmbuf_free(m);
            break;
        }
    }
}

void route_xmit(struct rte_mbuf *m, 
    __rte_unused struct module *peer, struct module *route)
{
    RTE_SET_USED(route);
    
    fastpath_log_error("no protocol installed for now, may be later\n");
    
    rte_pktmbuf_free(m);
}

int route_handle_msg(struct module *route, 
    struct msg_hdr *req, struct msg_hdr *resp)
{
    int ret;
    resp->cmd = req->cmd;

    fastpath_log_debug("route_handle_msg: cmd %d\n", req->cmd);
    
    switch (req->cmd) {
    case ROUTE_MSG_ADD_NEIGH:
        {
            struct arp_add *add = (struct arp_add *)req->data;
            struct nh_entry nh = {
                .nh_ip = rte_be_to_cpu_32(add->nh_ip),
                .nh_iface = rte_be_to_cpu_32(add->nh_iface),
            };
            struct arp_entry neigh = {
                .type = rte_be_to_cpu_16(add->type),
            };

            memcpy(&neigh.nh_arp, &add->nh_arp, sizeof(struct ether_addr));

            fastpath_log_debug("add nh "NIPQUAD_FMT" iface %d arp "MAC_FMT" type %d\n",
                HIPQUAD(nh.nh_ip), nh.nh_iface, MAC_ARG(&neigh.nh_arp), neigh.type);
            
            ret = neigh_add(route, &nh, &neigh);
            if (ret != 0) {
                fastpath_log_error("neigh_add failed\n");
                resp->flag = FASTPATH_MSG_FAILED;
            }
        }
        break;
    case ROUTE_MSG_DEL_NEIGH:
        {
            struct arp_del *del = (struct arp_del *)req->data;
            struct nh_entry nh = {
                .nh_ip = rte_be_to_cpu_32(del->nh_ip),
                .nh_iface = rte_be_to_cpu_32(del->nh_iface),
            };
            ret = neigh_del(route, &nh);
            if (ret != 0) {
                fastpath_log_error("neigh_del failed\n");
                resp->flag = FASTPATH_MSG_FAILED;
            }
        }
        break;
    case ROUTE_MSG_ADD_NH:
        {
            struct route_add *rt = (struct route_add *)req->data;
            struct lpm_key key = {
                .ip = rte_be_to_cpu_32(rt->ip),
                .depth = rt->depth,
            };
            struct nh_entry entry = {
                .nh_ip = rte_be_to_cpu_32(rt->nh_ip),
                .nh_iface = rte_be_to_cpu_32(rt->nh_iface),
            };

            fastpath_log_debug("add ip "NIPQUAD_FMT" depth %d next hop "NIPQUAD_FMT" interface %d\n",
                NIPQUAD(rt->ip), rt->depth, NIPQUAD(rt->nh_ip), rte_be_to_cpu_32(rt->nh_iface));
            
            ret = nh_add(route, &key, &entry);
            if (ret != 0) {
                fastpath_log_error("nh_add failed\n");
                resp->flag = FASTPATH_MSG_FAILED;
            }
        }
        break;
    case ROUTE_MSG_DEL_NH:
        {
            struct route_del *rt = (struct route_del *)req->data;
            struct lpm_key key = {
                .ip = rt->ip,
                .depth = rt->depth,
            };
            ret = nh_del(route, &key);
            if (ret != 0) {
                fastpath_log_error("nh_del failed\n");
                resp->flag = FASTPATH_MSG_FAILED;
            }
        }
        break;
    case ROUTE_MSG_ADD_NH6:
        {
            struct route6_add *rt = (struct route6_add *)req->data;
            struct lpm6_key key;
            struct nh6_entry entry;

            memcpy(&key.ip, rt->ip, sizeof(rt->ip));
            key.depth = rt->depth;
            memcpy(&entry.nh_ip, rt->nh_ip, sizeof(rt->nh_ip));
            entry.nh_iface = rt->nh_iface;
            
            ret = nh6_add(route, &key, &entry);
        }
        break;
    case ROUTE_MSG_DEL_NH6:
        {
            struct route6_del *rt = (struct route6_del *)req->data;
            struct lpm6_key key;

            memcpy(&key.ip, rt->ip, sizeof(rt->ip));
            key.depth = rt->depth;
            
            ret = nh6_del(route, &key);
        }
        break;
    default:
        break;
    }

    return ret;
}

void neigh_init(struct module *route)
{
    struct route_private *private = (struct route_private *)route->private;

    struct rte_hash_parameters ipv4_neigh_hash_params = {
        .name = "neigh_hash_ipv4",
        .entries = FASTPATH_NEIGH_HASH_ENTRIES,
        .bucket_entries = 8,
        .key_len = sizeof(struct nh_entry),
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };

    struct rte_hash_parameters ipv6_neigh_hash_params = {
        .name = "neigh_hash_ipv6",
        .entries = FASTPATH_NEIGH_HASH_ENTRIES,
        .bucket_entries = 8,
        .key_len = sizeof(struct nh6_entry),
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };

    private->neigh_tbl = rte_zmalloc(NULL, 
        FASTPATH_NEIGH_HASH_ENTRIES * sizeof(struct arp_entry), 0);
    if (private->neigh_tbl == NULL) {
        rte_panic("neigh_init: Unable to create neigh table\n");
        return;
    }

    private->neigh_hash_tbl = rte_hash_create(&ipv4_neigh_hash_params);
    if (private->neigh_hash_tbl == NULL) {
        rte_panic("neigh_init: Unable to create the ipv4 neigh hash\n");
        return;
    }

    private->neigh_hash_tbl6 = rte_hash_create(&ipv6_neigh_hash_params);
    if (private->neigh_hash_tbl6 == NULL) {
        rte_panic("neigh_init: Unable to create the ipv6 neigh hash\n");
        return;
    }
}

void lpm_init(struct module *route)
{
    struct rte_lpm *lpm;
    struct rte_lpm6 *lpm6;
    struct route_private *private = (struct route_private *)route->private;

    struct rte_lpm6_config lpm6_config = {
        .max_rules = FASTPATH_MAX_LPM6_RULES,
        .number_tbl8s = FASTPATH_LPM6_NUMBER_TBL8S,
        .flags = 0
    };

    private->default_nh = rte_zmalloc(NULL, sizeof(struct nh_entry), 0);
    if (private->default_nh == NULL) {
        rte_panic("Cannot malloc default entry\n");
        return;
    }

    private->default_nh6 = rte_zmalloc(NULL, sizeof(struct nh6_entry), 0);
    if (private->default_nh6 == NULL) {
        rte_panic("Cannot malloc default entry\n");
        return;
    }

    private->nh_tbl = rte_zmalloc(NULL, sizeof(struct nh_table), 0);
    if (private->nh_tbl == NULL) {
        rte_panic("Cannot malloc Next Hop table\n");
        return;
    }

    lpm = rte_lpm_create("route_lpm", rte_socket_id(), FASTPATH_MAX_LPM_RULES, 0);
    if (lpm == NULL) {
        rte_panic("Cannot create LPM table\n");
        return;
    }
    private->lpm_tbl = lpm;

    lpm6 = rte_lpm6_create("route_lpm6", rte_socket_id(), &lpm6_config);
    if (lpm6 == NULL) {
        rte_panic("Cannot create LPM6 table\n");
        return;
    }
    private->lpm6_tbl = lpm6;

    return;
}

int route_connect(struct module *local, struct module *peer, void *param)
{
    struct route_private *private;

    if (local == NULL || peer == NULL) {
        fastpath_log_error("route_connect: invalid local %p peer %p\n", 
            local, peer);
        return -EINVAL;
    }

    fastpath_log_info("route_connect: local %s peer %s\n", local->name, peer->name);

    private = (struct route_private *)local->private;

    if (peer->type == MODULE_TYPE_INTERFACE) {
        uint16_t ifidx = *(uint16_t *)param;
        if (ifidx >= ROUTE_MAX_LINK) {
            fastpath_log_error("route_connect: invalid ifidx %d\n", ifidx);
            return -EINVAL;
        }

        fastpath_log_info("route_connect: route add interface %d %s\n", ifidx, peer->name);
        
        private->ipv4[ifidx] = peer;

        peer->connect(peer, local, NULL);
    } else {
        fastpath_log_error("route_connect: invalid peer type %d\n", peer->type);
        return -ENOENT;
    }

    return 0;
}

struct module * route_init(void)
{
    struct module *route;
    struct route_private *private;

    route = rte_zmalloc(NULL, sizeof(struct module), 0);
    if (route == NULL) {
        fastpath_log_error("route_init: malloc module failed\n");
        return NULL;
    }

    private = rte_zmalloc(NULL, sizeof(struct route_private), 0);
    if (private == NULL) {
        rte_free(route);
        
        fastpath_log_error("route_init: malloc route_private failed\n");
        return NULL;
    }

    route->type = MODULE_TYPE_ROUTE;
    route->receive = route_receive;
    route->transmit = route_xmit;
    route->connect = route_connect;
    route->message = route_handle_msg;
    snprintf(route->name, sizeof(route->name), "route");

    route->private = private;

    neigh_init(route);
    lpm_init(route);

    route_module = route;

    return route;
}


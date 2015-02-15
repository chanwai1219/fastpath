
#include "fastpath.h"

#define NEIGH_TYPE_LOCAL        1
#define NEIGH_TYPE_REACHABLE    2
#define NEIGH_TYPE_UNRESOLVED   3

struct arp_entry {
    uint16_t type;
    struct ether_addr nh_arp;
};

struct nh_entry {
    uint32_t nh_ip;
    uint32_t nh_iface;
};

/* Next Hop Table (NHT) */
struct nh_table {
    uint32_t nht_users[FASTPATH_LPM_MAX_NEXT_HOPS];
    struct nh_entry nht[FASTPATH_LPM_MAX_NEXT_HOPS];
} __rte_cache_aligned;

struct route_private {
    struct module *ipv4[ROUTE_MAX_LINK];
    struct module *ipv6[ROUTE_MAX_LINK];
    struct rte_lpm *lpm_tbl;
    struct rte_lpm6 *lpm6_tbl;
    struct nh_table *nh_tbl;
    struct nh_entry *default_nh;
    struct rte_hash *neigh_hash_tbl;
    struct arp_entry *neigh_tbl;
} __rte_cache_aligned;

struct module *route_module;

static void neigh_init(struct module *route);
static void lpm_init(struct module *route);

void route_receive(struct rte_mbuf *m, 
    __rte_unused struct module *peer, struct module *route)
{
    uint8_t next_hop;
    int neigh_idx;
    struct ipv4_hdr *ipv4_hdr;
    struct ipv6_hdr *ipv6_hdr;
    struct nh_entry *nh;
    struct arp_entry *neigh;
    struct route_private *private = (struct route_private *)route->private;
    struct fastpath_pkt_metadata *c =
        (struct fastpath_pkt_metadata *)RTE_MBUF_METADATA_UINT8_PTR(m, 0);
    
    if (c->protocol == ETHER_TYPE_IPv4) {
        ipv4_hdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);
        
        /* Find destination port */
        if (rte_lpm_lookup(private->lpm_tbl, 
            rte_be_to_cpu_32(ipv4_hdr->dst_addr), &next_hop) == 0) {
            nh = &private->nh_tbl->nht[next_hop];
        } else {
            nh = private->default_nh;
        }

        if (nh == NULL) {
            fastpath_log_debug("lpm entry for "NIPQUAD_FMT" not found, drop packet\n",
                NIPQUAD(ipv4_hdr->dst_addr));
            rte_pktmbuf_free(m);
            return;
        }

        neigh_idx = rte_hash_lookup(private->neigh_hash_tbl, (void *)nh);
        if (neigh_idx < 0) {
            fastpath_log_debug("neigh entry for "NIPQUAD_FMT" not found, drop packet\n",
                NIPQUAD(nh->nh_ip));
            rte_pktmbuf_free(m);
            return;
        }

        neigh = &private->neigh_tbl[neigh_idx];
        switch (neigh->type) {
        case NEIGH_TYPE_LOCAL:
            fastpath_log_debug("route receive proto %d packet, will be supported later\n",
                ipv4_hdr->next_proto_id);
            rte_pktmbuf_free(m);
            break;

        case NEIGH_TYPE_REACHABLE:
            rte_memcpy(rte_pktmbuf_mtod(m, char *) - sizeof(struct ether_hdr), 
                &neigh->nh_arp, sizeof(struct ether_hdr));
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
            nh = &private->nh_tbl->nht[next_hop];
        } else {
            nh = private->default_nh;
        }

        if (nh == NULL) {
            fastpath_log_debug("lpm6 entry for "NIP6_FMT" not found, drop packet\n",
                NIP6(ipv6_hdr->dst_addr));
            rte_pktmbuf_free(m);
            return;
        }

        neigh_idx = rte_hash_lookup(private->neigh_hash_tbl, (void *)nh);
        if (neigh_idx < 0) {
            fastpath_log_debug("neigh entry for "NIP6_FMT" not found, drop packet\n",
                NIP6(ipv6_hdr->dst_addr));
            rte_pktmbuf_free(m);
            return;
        }

        neigh = &private->neigh_tbl[neigh_idx];
        if (neigh == NULL) {
            fastpath_log_debug("lpm6 entry for "NIP6_FMT" not found, drop packet\n",
                NIP6(ipv6_hdr->dst_addr));
            rte_pktmbuf_free(m);
            return;
        }

        switch (neigh->type) {
        case NEIGH_TYPE_LOCAL:
            fastpath_log_debug("route receive proto %d packet, will be supported later\n",
                ipv6_hdr->proto);
            rte_pktmbuf_free(m);
            break;

        case NEIGH_TYPE_REACHABLE:
            rte_memcpy(rte_pktmbuf_mtod(m, char *) - sizeof(struct ether_hdr), 
                &neigh->nh_arp, sizeof(struct ether_hdr));
            SEND_PKT(m, route, private->ipv6[nh->nh_iface], PKT_DIR_XMIT);
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

void neigh_init(struct module *route)
{
    struct route_private *private = (struct route_private *)route->private;

    struct rte_hash_parameters neigh_hash_params = {
        .name = "neigh_hash",
        .entries = FASTPATH_NEIGH_HASH_ENTRIES,
        .bucket_entries = 8,
        .key_len = sizeof(struct nh_entry),
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };

    private->neigh_hash_tbl = rte_hash_create(&neigh_hash_params);
    if (private->neigh_hash_tbl == NULL) {
        rte_panic("neigh_init: Unable to create the neigh hash\n");
        return;
    }

    fastpath_log_info("route create neigh hash table %s\n", neigh_hash_params.name);
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
    snprintf(route->name, sizeof(route->name), "route");

    route->private = private;

    neigh_init(route);
    lpm_init(route);

    route_module = route;

    return route;
}



#include "fastpath.h"

#define BRIDGE_HASH_ENTRIES     (64 * 1024)

#define BRIDGE_FDB_FLAG_DYNAMIC 0x01
#define BRIDGE_FDB_FLAG_STATIC  0x02
#define BRIDGE_FDB_FLAG_LOCAL   0x10

#define BRIDGE_MAX_PORTS        16
#define BRIDGE_INVALID_PORT     0xFF

struct bridge_fdb_entry {
    uint8_t port;
    uint8_t flag;
};

struct bridge_private {
    uint16_t vid;
    uint16_t port_num;
    struct module *interface;
    struct module *port[BRIDGE_MAX_PORTS];
    rte_spinlock_t lock[FASTPATH_MAX_SOCKETS];
    struct rte_hash *bridge_hash_tbl[FASTPATH_MAX_SOCKETS];
    struct bridge_fdb_entry *bridge_fdb[BRIDGE_HASH_ENTRIES];
};

struct module *bridge_dev[VLAN_VID_MAX];

static uint8_t bridge_get_port(struct module *br, struct module *port);
static void bridge_flood(struct rte_mbuf *m, struct module *br, uint8_t input);
static struct bridge_fdb_entry * bridge_fdb_lookup(struct module *br, struct ether_addr* ea);
static struct bridge_fdb_entry * bridge_fdb_create(uint8_t port, uint8_t flag);
static int bridge_fdb_update(struct module *br, struct ether_addr *addr, uint8_t index);
static int bridge_fdb_init(struct module *br);

static uint8_t bridge_get_port(struct module *br, struct module *port)
{
    uint32_t i;
    struct bridge_private *private = (struct bridge_private *)br->private;

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
        if (private->port[i] == port) {
            return i;
        }
    }

    return BRIDGE_INVALID_PORT;
}

static inline struct rte_mbuf *
bridge_out_pkt(struct rte_mbuf *pkt, int use_clone)
{
    int socketid;
    struct rte_mbuf *hdr;
    struct rte_mempool *mp;

    socketid = rte_socket_id();
    mp = fastpath.indirect_pools[socketid];

    /* Create new mbuf for the header. */
    if (unlikely ((hdr = rte_pktmbuf_alloc(mp)) == NULL))
        return (NULL);

    /* If requested, then make a new clone packet. */
    if (use_clone != 0 &&
        unlikely ((pkt = rte_pktmbuf_clone(pkt, mp)) == NULL)) {
        rte_pktmbuf_free(hdr);
        return (NULL);
    }

    /* prepend new header */
    hdr->next = pkt;


    /* update header's fields */
    hdr->pkt_len = (uint16_t)(hdr->data_len + pkt->pkt_len);
    hdr->nb_segs = (uint8_t)(pkt->nb_segs + 1);

    /* copy metadata from source packet*/
    hdr->port = pkt->port;
    hdr->vlan_tci = pkt->vlan_tci;
    hdr->tx_offload = pkt->tx_offload;
    hdr->hash = pkt->hash;

    hdr->ol_flags = pkt->ol_flags;

    __rte_mbuf_sanity_check(hdr, 1);
    return (hdr);
}

static void bridge_flood(struct rte_mbuf *m, struct module *br, uint8_t input)
{
    uint32_t i, clone_num, use_clone;
    struct rte_mbuf *mc;
    struct bridge_private *private = (struct bridge_private *)br->private;

    clone_num = private->port_num;

    use_clone = (private->port_num <= FASTPATH_CLONE_PORTS 
        && m->nb_segs <= FASTPATH_CLONE_SEGS);

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
        if (i != input && private->port[i] != NULL) {
            if (clone_num > 1) {
                if (likely((mc = bridge_out_pkt(m, use_clone)) != NULL)) {
                    SEND_PKT(mc, br, private->port[i]);
                } else if (use_clone == 0) {
                    rte_pktmbuf_free(m);
                    return;
                }
            } else {
                /* last pkt */
                if (use_clone != 0) {
                    if (input == BRIDGE_MAX_PORTS) {
                        SEND_PKT(m, br, private->interface);
                    } else {
                        SEND_PKT(m, br, private->port[i]);
                    }
                } else {
                    rte_pktmbuf_free(m);
                }

                break;
            }
        }

        clone_num--;
    }

    return;
}

void bridge_receive(struct rte_mbuf *m, 
    struct module *peer, struct module *br)
{
    uint8_t port;
    struct ether_hdr *eth_hdr;
    struct bridge_fdb_entry *entry;
    struct bridge_private *private = (struct bridge_private *)br->private;

    eth_hdr = (struct ether_hdr *)(rte_pktmbuf_mtod(m, char *) - sizeof(struct ether_hdr));

    port = bridge_get_port(br, peer);
    if (port == BRIDGE_INVALID_PORT) {
        fastpath_log_error("dev %s doest not participate in bridge %s\n", 
            peer->name, br->name);
        rte_pktmbuf_free(m);
        return;
    }

    fastpath_log_debug("bridge %s receive packet "MAC_FMT" ==> "MAC_FMT" from %d\n",
        MAC_ARG(&eth_hdr->s_addr), MAC_ARG(&eth_hdr->d_addr), port);
    
    if (!is_valid_assigned_ether_addr(&eth_hdr->s_addr)) {
        fastpath_log_error("bridge %s receive invalid packet\n", br->name);
        rte_pktmbuf_free(m);
        return;
    }

    if (bridge_fdb_update(br, &eth_hdr->s_addr, port) < 0) {
        fastpath_log_error("bridge %s update source address failed\n", br->name);
        rte_pktmbuf_free(m);
        return;
    }

    entry = bridge_fdb_lookup(br, &eth_hdr->d_addr);
    if (entry == NULL) {
        if (is_multicast_ether_addr(&eth_hdr->d_addr)) {
            bridge_flood(m, br, port);
        }
    } else {
        if (entry->flag & BRIDGE_FDB_FLAG_LOCAL) {
            SEND_PKT(m, br, private->interface);
        } else {
            SEND_PKT(m, br, private->port[entry->port]);
        }
    }
}

void bridge_xmit(struct rte_mbuf *m, 
    __rte_unused struct module *peer, struct module *br)
{
    struct bridge_fdb_entry *entry;
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    struct bridge_private *private = (struct bridge_private *)br->private;

    if (is_multicast_ether_addr(&eth_hdr->d_addr)) {
        bridge_flood(m, br, BRIDGE_MAX_PORTS);
    } else {
        entry = bridge_fdb_lookup(br, &eth_hdr->d_addr);
        if (entry == NULL) {
            bridge_flood(m, br, BRIDGE_MAX_PORTS);
            return;
        }

        SEND_PKT(m, br, private->port[entry->port]);
    }
}

struct bridge_fdb_entry * bridge_fdb_lookup(struct module *br, struct ether_addr* ea)
{
    int ret;
    int socketid;
    struct bridge_private *private = (struct bridge_private *)br->private;

    socketid = rte_socket_id();
    ret = rte_hash_lookup(private->bridge_hash_tbl[socketid], (const void *)ea);
    if (ret < 0) {
        return NULL;
    }
    
    return private->bridge_fdb[ret];
}

struct bridge_fdb_entry * bridge_fdb_create(uint8_t port, uint8_t flag)
{
    struct bridge_fdb_entry *entry;

    entry = rte_zmalloc(NULL, sizeof(struct bridge_fdb_entry), 0);
    if (entry == NULL) {
        fastpath_log_error("bridge_fdb_create: malloc failed\n");
        return NULL;
    }

    entry->flag = flag;
    entry->port = port;

    return entry;
}

int bridge_fdb_update(struct module *br, 
    struct ether_addr *addr, uint8_t port)
{
    int ret;
    int socketid;
    struct bridge_fdb_entry *entry;
    struct bridge_private *private = (struct bridge_private *)br->private;

    entry = bridge_fdb_lookup(br, addr);
    if (entry != NULL) {
        if (entry->port != port) {
            entry->port = port;
        }

        return 0;
    }

    entry = bridge_fdb_create(port, BRIDGE_FDB_FLAG_DYNAMIC);
    if (entry == NULL) {
        return -ENOMEM;
    }

    socketid = rte_socket_id();
    rte_spinlock_lock(&private->lock[socketid]);
    ret = rte_hash_add_key(private->bridge_hash_tbl[socketid], (void *)addr);
    if (ret < 0) {
        rte_spinlock_unlock(&private->lock[socketid]);
        fastpath_log_error("bridge_fdb_update: add key failed\n");
        return ret;
    }

    if (private->bridge_fdb[ret] == NULL) {
        private->bridge_fdb[ret] = entry;
    } else {
        rte_free(entry);
        entry = private->bridge_fdb[ret];
        entry->port = port;
    }

    rte_spinlock_unlock(&private->lock[socketid]);

    return 0;
}

int bridge_fdb_init(struct module *br)
{
    char s[64];
    int socketid;
    unsigned lcore_id;
    struct bridge_private *private = (struct bridge_private *)br->private;

    struct rte_hash_parameters bridge_hash_params = {
        .name = NULL,
        .entries = BRIDGE_HASH_ENTRIES,
        .bucket_entries = 8,
        .key_len = sizeof(struct ether_addr),
    };
    
    for (lcore_id = 0; lcore_id < FASTPATH_MAX_LCORES; lcore_id++) {
        socketid = rte_lcore_to_socket_id(lcore_id);

        if (private->bridge_hash_tbl[socketid] != NULL) {
            continue;
        }

        snprintf(s, sizeof(s), "br%d_hash_%d", private->vid, socketid);
        bridge_hash_params.name = s;
        bridge_hash_params.socket_id = socketid;

        rte_spinlock_init(&private->lock[socketid]);
        private->bridge_hash_tbl[socketid] = rte_hash_create(&bridge_hash_params);
        if (private->bridge_hash_tbl[socketid] == NULL) {
            fastpath_log_error("bridge_fdb_init: malloc %s failed\n", bridge_hash_params.name);

            for (socketid = 0; socketid < FASTPATH_MAX_SOCKETS; socketid++) {
                if (private->bridge_hash_tbl[socketid] != NULL) {
                    rte_hash_free(private->bridge_hash_tbl[socketid]);
                }
            }
            
            return -ENOMEM;
        }

        fastpath_log_info("bridge %s create hash table %s\n", br->name, bridge_hash_params.name);
    }

    return 0;
}

int bridge_add_if(struct module *br, struct module *port)
{
    uint32_t i;
    struct bridge_private *private = (struct bridge_private *)br->private;
    
    if (port->type != MODULE_TYPE_ETHERNET && port->type != MODULE_TYPE_VLAN) {
        fastpath_log_error("bridge_add_if: add port type %d failed\n", port->type);
        return -EINVAL;
    }

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
        if (private->port[i] != NULL) {
            break;
        }
    }
    if (i == BRIDGE_MAX_PORTS) {
        fastpath_log_error("bridge_add_if: bridge %s already has %d ports\n", port->name, i);
        return -EINVAL;
    }

    private->port[i] = port;
    private->port_num += 1;

    fastpath_log_info("bridge %s add port %s index %d\n", br->name, port->name, i);

    return 0;
}

int bridge_del_if(struct module *br, struct module *port)
{
    uint32_t i;
    struct bridge_private *private = (struct bridge_private *)br->private;

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
        if (private->port[i] == port) {
            break;
        }
    }

    if (i == BRIDGE_MAX_PORTS) {
        fastpath_log_error("bridge_del_if: delete %s from %s failed\n", port->name, br->name);
        return -ENOENT;
    }
    
    private->port[i] = NULL;
    private->port_num -= 1;

    fastpath_log_info("bridge %s delete port %s index %d\n", br->name, port->name, i);

    return 0;
}

int bridge_init(uint16_t vid)
{
    struct module *br;
    struct bridge_private *private;
    
    if (vid > VLAN_VID_MASK) {
        fastpath_log_error("bridge_init: bridge %d already initialized\n", vid);
        return -EINVAL;
    }

    br = rte_zmalloc(NULL, sizeof(struct module), 0);
    if (br == NULL) {
        fastpath_log_error("bridge_init: malloc module failed\n");
        return -ENOMEM;
    }

    private = rte_zmalloc(NULL, sizeof(struct bridge_private), 0);
    if (private == NULL) {
        rte_free(br);
        
        fastpath_log_error("bridge_init: malloc bridge_private failed\n");
        return -ENOMEM;
    }

    br->ifindex = 0;
    br->type = MODULE_TYPE_BRIDGE;
    snprintf(br->name, sizeof(br->name), "br%d", vid);
    
    private->vid = vid;
    private->port_num = 0;
    if (bridge_fdb_init(br) != 0) {
        rte_free(private);
        rte_free(br);

        return -ENOMEM;
    }
    
    br->private = (void *)private;

    bridge_dev[vid] = br;

    return 0;
}

int bridge_fini(void)
{
    return 0;    
}


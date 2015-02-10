
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
    struct net_device *interface_dev;
    struct net_device *port_dev[BRIDGE_MAX_PORTS];
    struct rte_hash *bridge_hash_tbl[FASTPATH_MAX_SOCKETS];
    struct bridge_fdb_entry *bridge_fdb[BRIDGE_HASH_ENTRIES];
};

struct net_device *bridge_dev[VLAN_VID_MAX];

static uint8_t bridge_get_port(struct net_device *br, struct net_device *dev);
static void bridge_flood(struct rte_mbuf *m, struct net_device *br, uint8_t input);
static struct bridge_fdb_entry * bridge_fdb_lookup(struct net_device *dev, struct ether_addr* ea);
static struct bridge_fdb_entry * bridge_fdb_create(uint8_t port, uint8_t flag);
static int bridge_fdb_update(struct net_device *dev, struct ether_addr *addr, uint8_t index);
static int bridge_fdb_init(struct net_device *br);

static uint8_t bridge_get_port(struct net_device *br, struct net_device *dev)
{
    uint32_t i;
    struct bridge_private *private = (struct bridge_private *)br->private;

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
        if (private->port_dev[i] == dev) {
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

static void bridge_flood(struct rte_mbuf *m, struct net_device *br, uint8_t input)
{
    uint32_t i, clone_num, use_clone;
    struct rte_mbuf *mc;
    struct net_device *dst[BRIDGE_MAX_PORTS];
    struct bridge_private *private = (struct bridge_private *)br->private;

    memset(dst, 0, sizeof(dst));

    clone_num = 0;

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
        if (input != i && private->port_dev[i] != NULL) {
            dst[clone_num] = private->port_dev[i];
            clone_num++;
        }
    }
    if (input == BRIDGE_MAX_PORTS) {
        dst[clone_num] = private->interface_dev;
        clone_num++;
    }

    use_clone = (private->port_num <= FASTPATH_CLONE_PORTS 
        && m->nb_segs <= FASTPATH_CLONE_SEGS);

    if (use_clone == 0) {
        rte_pktmbuf_refcnt_update(m, (uint16_t)clone_num);
    }

    for (i = 0; i < (clone_num - 1); i++) {
        if (likely((mc = bridge_out_pkt(m, use_clone)) != NULL)) {
            SEND_PKT(mc, br, dst[i]);
        } else if (use_clone == 0) {
            rte_pktmbuf_free(m);
            return;
        }
    }

    if (use_clone != 0) {
        SEND_PKT(m, br, dst[clone_num - 1]);
    } else {
        rte_pktmbuf_free(m);
    }
}

void bridge_receive(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev)
{
    uint8_t port;
    struct ether_hdr *eth;
    struct bridge_fdb_entry *entry;
    struct bridge_private *private = (struct bridge_private *)dev->private;

    eth = (struct ether_hdr *)(rte_pktmbuf_mtod(m, char *) - sizeof(struct ether_hdr));

    port = bridge_get_port(dev, peer);
    if (port == BRIDGE_INVALID_PORT) {
        fastpath_log_error("dev %s doest not participate in bridge %s\n", 
            peer->name, dev->name);
        rte_pktmbuf_free(m);
        return;
    }

    fastpath_log_debug("bridge %s receive packet "MAC_FMT" ==> "MAC_FMT" from %d\n",
        MAC_ARG(&eth->s_addr), MAC_ARG(&eth->d_addr), port);
    
    if (!is_valid_assigned_ether_addr(&eth->s_addr)) {
        fastpath_log_error("bridge %s receive invalid packet\n", dev->name);
        rte_pktmbuf_free(m);
        return;
    }

    if (bridge_fdb_update(dev, &eth->s_addr, port) < 0) {
        fastpath_log_error("bridge %s update source address failed\n", dev->name);
        rte_pktmbuf_free(m);
        return;
    }

    entry = bridge_fdb_lookup(dev, &eth->d_addr);
    if (entry == NULL) {
        if (is_multicast_ether_addr(&eth->d_addr)) {
            bridge_flood(m, dev, port);
        }
    } else {
        if (entry->flag & BRIDGE_FDB_FLAG_LOCAL) {
            SEND_PKT(m, dev, private->interface_dev);
        } else {
            SEND_PKT(m, dev, private->port_dev[entry->port]);
        }
    }
}

void bridge_xmit(struct rte_mbuf *m, __rte_unused struct net_device *peer, struct net_device *dev)
{
    struct bridge_fdb_entry *entry;
    struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    struct bridge_private *private = (struct bridge_private *)dev->private;

    if (is_multicast_ether_addr(&eth->d_addr)) {
        bridge_flood(m, dev, BRIDGE_MAX_PORTS);
    } else {
        entry = bridge_fdb_lookup(dev, &eth->d_addr);
        if (entry == NULL) {
            bridge_flood(m, dev, BRIDGE_MAX_PORTS);
            return;
        }

        SEND_PKT(m, dev, private->port_dev[entry->port]);
    }
}

struct bridge_fdb_entry * bridge_fdb_lookup(struct net_device *dev, struct ether_addr* ea)
{
    int ret;
    int socketid;
    struct bridge_private *private = (struct bridge_private *)dev->private;

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

int bridge_fdb_update(struct net_device *dev, 
    struct ether_addr *addr, uint8_t port)
{
    int ret;
    int socketid;
    struct bridge_fdb_entry *entry;
    struct bridge_private *private = (struct bridge_private *)dev->private;

    entry = bridge_fdb_lookup(dev, addr);
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
    ret = rte_hash_add_key(private->bridge_hash_tbl[socketid], (void *)addr);
    if (ret < 0) {
        fastpath_log_error("bridge_fdb_update: add key failed\n");
        return ret;
    }

    private->bridge_fdb[ret] = entry;

    return 0;
}

int bridge_fdb_init(struct net_device *br)
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

int bridge_add_if(struct net_device *br, struct net_device *dev)
{
    uint32_t i;
    struct bridge_private *private = (struct bridge_private *)br->private;
    
    if (dev->type != NET_DEVICE_TYPE_ETHERNET && dev->type != NET_DEVICE_TYPE_VLAN) {
        fastpath_log_error("bridge_add_if: add dev type %d failed\n", dev->type);
        return -EINVAL;
    }

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
        if (private->port_dev[i] != NULL) {
            break;
        }
    }
    if (i == BRIDGE_MAX_PORTS) {
        fastpath_log_error("bridge_add_if: bridge %s already has %d ports\n", dev->name, i);
        return -EINVAL;
    }

    private->port_dev[i] = dev;
    private->port_num += 1;

    fastpath_log_info("bridge %s add port %s index %d\n", br->name, dev->name, i);

    return 0;
}

int bridge_del_if(struct net_device *br, struct net_device *dev)
{
    uint32_t i;
    struct bridge_private *private = (struct bridge_private *)br->private;

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
        if (private->port_dev[i] == dev) {
            break;
        }
    }

    if (i == BRIDGE_MAX_PORTS) {
        fastpath_log_error("bridge_del_if: delete %s from %s failed\n", dev->name, br->name);
        return -ENOENT;
    }
    
    private->port_dev[i] = NULL;
    private->port_num -= 1;

    fastpath_log_info("bridge %s delete port %s index %d\n", br->name, dev->name, i);

    return 0;
}

int bridge_init(uint16_t vid)
{
    struct net_device *dev;
    struct bridge_private *private;
    
    if (vid > VLAN_VID_MASK) {
        fastpath_log_error("bridge_init: bridge %d already initialized\n", vid);
        return -EINVAL;
    }

    dev = rte_zmalloc(NULL, sizeof(struct net_device), 0);
    if (dev == NULL) {
        fastpath_log_error("bridge_init: malloc net_device failed\n");
        return -ENOMEM;
    }

    private = rte_zmalloc(NULL, sizeof(struct bridge_private), 0);
    if (private == NULL) {
        rte_free(dev);
        
        fastpath_log_error("bridge_init: malloc bridge_private failed\n");
        return -ENOMEM;
    }

    dev->ifindex = 0;
    dev->type = NET_DEVICE_TYPE_BRIDGE;
    snprintf(dev->name, sizeof(dev->name), "br%d", vid);
    
    private->vid = vid;
    private->port_num = 0;
    if (bridge_fdb_init(dev) != 0) {
        rte_free(private);
        rte_free(dev);

        return -ENOMEM;
    }
    
    dev->private = (void *)private;

    bridge_dev[vid] = dev;

    return 0;
}

int bridge_fini(void)
{
    return 0;    
}


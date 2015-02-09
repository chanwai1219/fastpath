
#include "fastpath.h"

#define BRIDGE_HASH_ENTRIES     (64 * 1024)

#define BRIDGE_FDB_FLAG_DYNAMIC 0x01
#define BRIDGE_FDB_FLAG_STATIC  0x02

#define BRIDGE_MAX_PORTS        16

struct net_device *bridge_dev[VLAN_VID_LEN];

struct bridge_fdb_entry {
    uint8_t port;
    uint8_t flag;
};

struct bridge_port {
    uint8_t port_no;
    uint8_t reserved[3];
    struct net_device *br;
    struct net_device *dev;
    LIST_ENTRY(bridge_port) list;
};

struct bridge_private {
    uint16_t vid;
    LIST_HEAD (, bridge_port) port_list;
    struct net_device *interface_dev;
    struct net_device *vlan_dev[BRIDGE_PORT_MAX];
    struct bridge_fdb_entry bridge_fdb[BRIDGE_HASH_ENTRIES];
    struct rte_hash *bridge_hash_tbl[NB_SOCKETS];
};

uint16_t bridge_get_port(struct net_device *bridge, struct net_device *vlan)
{
    uint32_t i;
    struct bridge_private *private = bridge->private;

    for (i = 0; i < BRIDGE_PORT_MAX; i++) {
        if (private->vlan_dev[i] == vlan) {
            return 
        }
    }
}

void bridge_receive(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev)
{
    uint16_t port;
    struct ether_hdr *eth;
    struct bridge_private *private = (struct bridge_private *)dev->private;

    eth = (struct ether_hdr *)(m->pkt.data - sizeof(struct ether_hdr));

    port = 

    fastpath_log_debug("bridge %s receive packet "MAC_FMT" ==> "MAC_FMT" from %d\n",
        MAC_ARG(&eth->s_addr), MAC_ARG(&eth->d_addr), private->port);
    
    if (!is_valid_assigned_ether_addr(&eth->s_addr)) {
        fastpath_log_error("bridge %s receive invalid packet\n", dev->name);
        rte_pktmbuf_free(m);
        return;
    }

    if (bridge_fdb_update(dev, eth->s_addr) < 0) {
        fastpath_log_error("bridge %s update source address failed\n", dev->name);
        rte_pktmbuf_free(m);
        return;
    }

    if (is_multicast_ether_addr(&eth->d_addr)) {
        
    }
}

void bridge_xmit(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev)
{
}

struct bridge_fdb_entry * bridge_fdb_lookup(struct net_device *dev, struct ether_addr* ea)
{
    int ret;
    int socketid;
    unsigned lcore_id;
    struct bridge_private *private = (struct bridge_private *)dev->private;

    lcore_id = rte_lcore_id();
    socketid = rte_lcore_to_socket_id(lcore_id);
    ret = rte_hash_lookup(private->brdige_hash_tbl[socketid], (const void *)ea);
    if (ret < 0) {
        return NULL;
    }
    
    return &private->bridge_fdb[ret];
}

struct bridge_fdb_entry * bridge_fdb_create(const struct ether_addr *addr, uint8_t port)
{
    struct bridge_fdb_entry *entry;

    entry = rte_zmalloc(NULL, sizeof(struct bridge_fdb_entry), 0);
    if (entry == NULL) {
        fastpath_log_error("bridge_fdb_create: malloc failed\n");
        return NULL;
    }

    entry->flag = BRIDGE_FDB_FLAG_DYNAMIC;
    entry->port = port;

    return entry;
}

int bridge_fdb_update(struct net_device *dev, const struct ether_addr *addr)
{
    int ret;
    int socketid;
    unsigned lcore_id;
    struct bridge_fdb_entry *entry;
    struct bridge_private *private = (struct bridge_private *)dev->private;

    entry = bridge_fdb_lookup(dev, addr);
    if (entry != NULL) {
        if (entry->port != private->port) {
            entry->port = private->port;
        }

        return 0;
    }

    entry = bridge_fdb_create(addr, private->port);
    if (entry == NULL) {
        return -1;
    }

    lcore_id = rte_lcore_id();
    socketid = rte_lcore_to_socket_id(lcore_id);
    ret = rte_hash_add_key(private->bridge_hash_tbl[socketid], addr);
    if (ret < 0) {
        fastpath_log_error("bridge_fdb_update: add key failed\n");
        return -1;
    }

    private->bridge_fdb[ret] = entry;

    return 0;
}

/* find an available port number */
static int find_portno(struct net_bridge *br)
{
    int index;
    struct net_bridge_port *p;
    unsigned long *inuse;

    inuse = rte_zmalloc(BITS_TO_LONGS(BR_MAX_PORTS), sizeof(unsigned long),
            GFP_KERNEL);
    if (!inuse)
        return -ENOMEM;

    set_bit(0, inuse);    /* zero is reserved */
    list_for_each_entry(p, &br->port_list, list) {
        set_bit(p->port_no, inuse);
    }
    index = find_first_zero_bit(inuse, BR_MAX_PORTS);
    kfree(inuse);

    return (index >= BR_MAX_PORTS) ? -EXFULL : index;
}

int bridge_add_if(struct net_device *br, struct net_device *dev)
{
    uint32_t index;
    unsigned long inuse;
    struct bridge_port *p;
    struct bridge_private *private = br->private;
    
    if (dev->type != NET_DEVICE_TYPE_ETHERNET && dev->type != NET_DEVICE_TYPE_VLAN) {
        fastpath_log_error("bridge_add_if: add dev type %d failed\n", dev->type);
        return -EINVAL;
    }

    inuse = 0;
    LIST_FOREACH(p, &private->port_list, list) {
        set_bit(p->port_no, &inuse);
    }
    index = find_first_zero_bit(&inuse, BRIDGE_MAX_PORTS);

    p = rte_zmalloc(NULL, sizeof(struct bridge_port), 0);
    if (p == NULL) {
        fastpath_log_error("bridge_add_if: add dev type %d failed\n", dev->type);
        return -ENOMEM;
    }

    p->br = br;
    p->dev = dev;
    p->index = index;

    LIST_INSERT_HEAD(&private->port_list, p, list);

    return 0;
}

int bridge_del_if(struct net_device *br, struct net_device *dev)
{
}

int bridge_fdb_init(struct bridge_private *private)
{
    int socketid;
    unsigned lcore_id;

    struct rte_hash_parameters bridge_hash_params = {
        .name = NULL,
        .entries = BRIDGE_HASH_ENTRIES,
        .bucket_entries = 8,
        .key_len = sizeof(struct ether_addr),
    };
    
    for (lcore_id = 0; lcore_id < FASTPATH_MAX_LCORES; lcore_id++) {
        socketid = rte_lcore_to_socket_id(lcore_id);

        if (private->brdige_hash_tbl[socketid] != NULL) {
            continue;
        }

        snprintf(bridge_hash_params.name, sizeof(bridge_hash_params.name), 
            "br%d_hash_%d", private->vid, socketid);
        bridge_hash_params.socket_id = socketid;

        private->brdige_hash_tbl[socketid] = rte_hash_create(&bridge_hash_params);
        if (private->brdige_hash_tbl[socketid] == NULL) {
            fastpath_log_error("bridge_fdb_init: malloc %s failed\n", bridge_hash_params.name);

            for (socketid = 0; socketid < NB_SOCKETS; socketid++) {
                if (private->brdige_hash_tbl[socketid] != NULL) {
                    rte_hash_free(private->brdige_hash_tbl[socketid]);
                }
            }
            
            return -1;
        }
    }
        
}

int bridge_init(uint16_t vid)
{
    struct net_device *dev;
    struct bridge_private *private;
    
    if (vid > VLAN_VID_MASK) {
        fastpath_log_error("bridge_init: bridge %d already initialized\n", vid);
        return -1;
    }

    dev = rte_zmalloc(NULL, sizeof(struct net_device), 0);
    if (dev == NULL) {
        fastpath_log_error("bridge_init: malloc net_device failed\n");
        return -1;
    }

    private = rte_zmalloc(NULL, sizeof(struct bridge_private), 0);
    if (private == NULL) {
        rte_free(dev);
        
        fastpath_log_error("bridge_init: malloc bridge_private failed\n");
        return -1;
    }

    dev->ifindex = 0;
    dev->type = NET_DEVICE_TYPE_BRIDGE;
    snprintf(dev->name, IFNAMSIZ, "br%d", vid);
    
    private->vid = vid;
    LIST_INIT(&private->port_list);
    if (bridge_fdb_init(private) != 0) {
        rte_free(private);
        rte_free(dev);

        return -1;
    }
    
    dev->private = (void *)private;

    bridge_dev[vid] = dev;

    return 0;
}

int bridge_fini()
{
    
}


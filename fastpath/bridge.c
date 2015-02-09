
#include "fastpath.h"

#define BRIDGE_HASH_ENTRIES     (64 * 1024)

#define BRIDGE_FDB_FLAG_DYNAMIC 0x01
#define BRIDGE_FDB_FLAG_STATIC  0x02
#define BRIDGE_FDB_FLAG_LOCAL   0x10

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
    struct net_device *port_dev[BRIDGE_MAX_PORTS];
    struct rte_hash *bridge_hash_tbl[NB_SOCKETS];
    struct bridge_fdb_entry bridge_fdb[BRIDGE_HASH_ENTRIES];
};

struct bridge_port * bridge_get_port(struct net_device *br, struct net_device *dev)
{
    struct bridge_port *p;
    struct bridge_private *private = (struct bridge_private *)br->private;

    LIST_FOREACH(p, &private->port_list, list) {
        if (p->dev == dev) {
            return p;
        }
    }

    return NULL;
}

void bridge_receive(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev)
{
    struct ether_hdr *eth;
    struct bridge_port *port;
    struct bridge_fdb_entry *entry;
    struct bridge_private *private = (struct bridge_private *)dev->private;

    eth = (struct ether_hdr *)(m->pkt.data - sizeof(struct ether_hdr));

    port = bridge_get_port(dev, peer);
    if (port == NULL) {
        fastpath_log_error("dev %s doest not participate in bridge %s\n", 
            peer->name, dev->name);
        rte_pktmbuf_free(m);
        return;
    }

    fastpath_log_debug("bridge %s receive packet "MAC_FMT" ==> "MAC_FMT" from %d\n",
        MAC_ARG(&eth->s_addr), MAC_ARG(&eth->d_addr), port->port_no);
    
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

    entry = bridge_fdb_lookup(dev, &eth->d_addr);
    if (entry == NULL) {
        if (is_multicast_ether_addr(&eth->d_addr)) {
            
        }
    } else {
        if (entry->flag & BRIDGE_FDB_FLAG_LOCAL) {
            SEND_PKT(m, dev, private->interface_dev);
        } else {
            SEND_PKT(m, dev, private->port_dev[entry->port]);
        }
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

int bridge_fdb_update(struct net_device *dev, 
    struct ether_addr *addr, struct bridge_port *port)
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
    entry->port = port->port_no;
    entry->flag = BRIDGE_FDB_FLAG_DYNAMIC;

    lcore_id = rte_lcore_id();
    socketid = rte_lcore_to_socket_id(lcore_id);
    ret = rte_hash_add_key(private->bridge_hash_tbl[socketid], (void *)addr);
    if (ret < 0) {
        fastpath_log_error("bridge_fdb_update: add key failed\n");
        return -1;
    }

    private->bridge_fdb[ret] = entry;

    return 0;
}

int bridge_add_if(struct net_device *br, struct net_device *dev)
{
    uint32_t index;
    unsigned long inuse;
    struct bridge_port *p;
    struct bridge_private *private = (struct bridge_private *)br->private;
    
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

    private->port_dev[index] = dev;

    fastpath_log_info("bridge %s add port %s index %d\n", br->name, dev->name, index);

    return 0;
}

int bridge_del_if(struct net_device *br, struct net_device *dev)
{
    struct bridge_port *p = NULL;
    struct bridge_private *private = (struct bridge_private *)br->private;

    LIST_FOREACH(p, &private->port_list, list) {
        if (p->dev == dev) {
            break;
        }
    }

    if (p == NULL) {
        return -ENOENT;
    }
    
    LIST_REMOVE(p, list);
    private->port_dev[p->index] = NULL;

    fastpath_log_info("bridge %s delete port %s index %d\n", br->name, dev->name, index);

    rte_free(p);

    return 0;
}

int bridge_fdb_init(struct net_device *br)
{
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
            
            return -ENOMEM;
        }

        fastpath_log_info("bridge %s create hash table %s\n", br->name, bridge_hash_params.name);
    }

    return 0;
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
    if (bridge_fdb_init(dev) != 0) {
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


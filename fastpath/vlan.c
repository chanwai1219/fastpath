
#include "fastpath.h"

#define VLAN_VID_LEN    4096
#define VLAN_VID_MASK	0xFFF

enum {
    VLAN_MODE_ACCESS,
    VLAN_MODE_TRUNK
};

struct net_device *vlan_dev[FASTPATH_MAX_NIC_PORTS];

typedef struct vlan_private {
    struct net_device *ethernet_dev;
    struct net_device *bridge_dev[VLAN_VID_LEN];
    uint16_t port;
    uint8_t mode;
    uint8_t native;
};

struct net_device * find_vlan_dev(uint32_t port)
{
    uint32_t i;
    struct net_device *dev;
    struct vlan_private *private;
    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("find_vlan_dev: invalid port %d\n", port);
        return NULL;
    }

    for (i = 0; i < VLAN_VID_LEN; i++) {
        dev = vlan_dev[i];
        if (dev == NULL) {
            continue;
        }

        private = (struct vlan_private *)dev->private;
        if (private->port == port) {
            return dev;
        }
    }

    return NULL;
}

int vlan_receive(struct rte_mbuf *m, struct net_device *dev)
{
    uint32_t vid;
    struct ether_hdr *eth;
    struct vlan_hdr  *vlan_hdr;
    struct vlan_private *private = (struct vlan_private *)dev->private;

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct ether_hdr));
    vlan_hdr = rte_pktmbuf_mtod(m, struct vlan_hdr *);
    
    if (ntohs(eth->ether_type) == ETHER_TYPE_VLAN) {
        vid = ntohs(vlan_hdr->vlan_tci);
        
        if (private->mode == VLAN_MODE_ACCESS) {
            fastpath_log_error("access vlan %s receive packet vid %x, drop\n", 
                dev->name, vid);
            rte_pktmbuf_free(m);
            return 0;
        } else {
            fastpath_log_debug("trunk vlan %s receive packet vid %x\n", 
                dev->name, vid);

            rte_pktmbuf_adj(m, (uint16_t)sizeof(struct vlan_hdr));
            memmove((char *)eth + sizeof(vlan_hdr), eth, 12);

            SEND_PKT(m, private->bridge_dev[vid]);
        }
    } else {
        if (private->mode == VLAN_MODE_ACCESS) {
            fastpath_log_debug("access vlan %s receive untagged packet, send to %d\n",
                dev->name, private->native);

            SEND_PKT(m, private->bridge_dev[private->native];
        } else {
            fastpath_log_debug("trunk vlan %s receive untagged packet, send to %d\n",
                dev->name, private->native);

            SEND_PKT(m, private->bridge_dev[private->native];
        }
    }
    
    return 0;
}

int vlan_xmit(struct rte_mbuf *m, struct net_device *dev)
{
    struct vlan_hdr  *vlan_hdr;
    struct vlan_private *private = (struct vlan_private *)dev->private;
    
    if (private->mode == VLAN_MODE_ACCESS) {
        SEND_PKT(private->ethernet_dev);
    } else {
        rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct vlan_hdr));
        vlan_hdr = rte_pktmbuf_mtod(m, struct vlan_hdr *);
        
    }
    
    SEND_PKT(m, private->ethernet_dev);
    return 0;
}

int vlan_set_ethernet(struct net_device *vlan, struct net_device *ethernet)
{
    struct vlan_private *private;

    if (vlan == NULL || ethernet == NULL) {
        fastpath_log_error("vlan_set_ethernet: invalid vlan %p ethernet %p\n", 
            vlan, ethernet);

        return -1;
    }
    
    private = (struct vlan_private *)vlan->private;
    private->ethernet_dev = ethernet;

    return 0;
}

int vlan_set_bridge(struct net_device *vlan, uint32_t vid, struct net_device *bridge)
{
    struct vlan_private *private;

    if (vlan == NULL || bridge == NULL) {
        fastpath_log_error("vlan_set_bridge: invalid vlan %p bridge %p\n", 
            vlan, ethernet);

        return -1;
    }

    if (vid > VLAN_VID_MASK) {
        fastpath_log_error("vlan_set_bridge: invalid vlan %d\n", vid);

        return -1;
    }
    
    private = (struct vlan_private *)vlan->private;
    private->bridge_dev[vid] = bridge;

    return 0;
}

int vlan_init(uint16_t port, uint16_t mode, uint16_t native, uint8_t *map)
{
    struct net_device *dev;
    struct vlan_private *private;
    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("vlan_init: invalid port %d\n", port);
        return -1;
    }

    if (mode != VLAN_MODE_ACCESS && mode != VLAN_MODE_TRUNK) {
        fastpath_log_error("vlan_init: invalid mode %d\n", mode);
        return -1;
    }

    dev = rte_malloc(NULL, sizeof(struct net_device), 0);
    if (dev == NULL) {
        fastpath_log_error("vlan_init: malloc net_device failed\n");
        return -1;
    }

    private = rte_malloc(NULL, sizeof(struct vlan_private), 0);
    if (private == NULL) {
        rte_free(dev);
        
        fastpath_log_error("vlan_init: malloc net_device failed\n");
        return -1;
    }

    memset(private, 0, sizeof(struct vlan_private));

    dev->ifindex = 0;
    snprintf(dev->name, IFNAMSIZ, "vlan%d", vid);
    
    private->port = port;
    private->mode = mode;
    private->native = native;
    memcpy(private->vid, map, sizeof(private->vid));
    
    dev->private = (void *)private;

    vlan_dev[port] = dev;

    return 0;
}


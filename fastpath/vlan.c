
#include "fastpath.h"

#define VLAN_VID_LEN    4096
#define VLAN_VID_MASK	0xFFF

enum {
    VLAN_MODE_ACCESS,
    VLAN_MODE_TRUNK
};

struct net_device *vlan_dev[FASTPATH_MAX_NIC_PORTS];

typedef struct vlan_private {
    uint16_t port;
    uint16_t vid;
    struct net_device *ethernet_dev;
    struct net_device *bridge_dev;
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

void vlan_receive(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev)
{
    struct vlan_hdr  *vlan_hdr;
    struct vlan_private *private = (struct vlan_private *)dev->private;

    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct vlan_hdr));
    memmove(m->pkt.data - sizeof(struct ether_hdr), 
        m->pkt.data - sizeof(struct ether_hdr) - sizeof(struct vlan_hdr), 
        2 * sizeof(struct ether_addr));

    SEND_PKT(m, dev, private->bridge_dev);
    
    return;
}

void vlan_xmit(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev)
{
    struct ether_hdr *eth;
    struct vlan_hdr  *vlan_hdr;
    struct vlan_private *private = (struct vlan_private *)dev->private;
    
    rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct vlan_hdr));
    memmove(m->pkt.data, m->pkt.data + sizeof(struct vlan_hdr), 
        2 * sizeof(struct ether_addr));
    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    vlan_hdr = (struct vlan_hdr *)(eth + 1);
    vlan_hdr->vlan_tci = htons(private->vid);
    vlan_hdr->eth_proto = htons(ETHER_TYPE_VLAN);    
    
    SEND_PKT(m, dev, private->ethernet_dev);
    
    return;
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

int vlan_init(uint16_t port)
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

    dev = rte_zmalloc(NULL, sizeof(struct net_device), 0);
    if (dev == NULL) {
        fastpath_log_error("vlan_init: malloc net_device failed\n");
        return -1;
    }

    private = rte_zmalloc(NULL, sizeof(struct vlan_private), 0);
    if (private == NULL) {
        rte_free(dev);
        
        fastpath_log_error("vlan_init: malloc net_device failed\n");
        return -1;
    }

    dev->ifindex = 0;
    dev->type = NET_DEVICE_TYPE_VLAN;
    snprintf(dev->name, IFNAMSIZ, "vlan%d", vid);
    
    private->port = port;
    
    dev->private = (void *)private;

    vlan_dev[port] = dev;

    return 0;
}


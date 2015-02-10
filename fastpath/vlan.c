
#include "fastpath.h"
#include "vlan.h"

struct net_device *vlan_dev[FASTPATH_MAX_NIC_PORTS];

struct vlan_private {
    uint16_t port;
    uint16_t vid;
    struct net_device *ethernet_dev;
    struct net_device *bridge_dev;
};

void vlan_receive(struct rte_mbuf *m, __rte_unused struct net_device *peer, struct net_device *dev)
{
    struct vlan_private *private = (struct vlan_private *)dev->private;

    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct vlan_hdr));
    memmove(rte_pktmbuf_mtod(m, char *) - sizeof(struct ether_hdr), 
        rte_pktmbuf_mtod(m, char *) - sizeof(struct ether_hdr) - sizeof(struct vlan_hdr), 
        2 * sizeof(struct ether_addr));

    SEND_PKT(m, dev, private->bridge_dev);
    
    return;
}

void vlan_xmit(struct rte_mbuf *m, __rte_unused struct net_device *peer, struct net_device *dev)
{
    struct ether_hdr *eth;
    struct vlan_hdr  *vlan_hdr;
    struct vlan_private *private = (struct vlan_private *)dev->private;
    
    rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct vlan_hdr));
    memmove(rte_pktmbuf_mtod(m, void *), 
        rte_pktmbuf_mtod(m, char *) + sizeof(struct vlan_hdr), 
        2 * sizeof(struct ether_addr));
    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    vlan_hdr = (struct vlan_hdr *)(eth + 1);
    vlan_hdr->vlan_tci = rte_cpu_to_be_16(private->vid);
    vlan_hdr->eth_proto = rte_cpu_to_be_16(ETHER_TYPE_VLAN);    
    
    SEND_PKT(m, dev, private->ethernet_dev);
    
    return;
}

int vlan_set_ethernet(struct net_device *vlan, struct net_device *ethernet)
{
    struct vlan_private *private;

    if (vlan == NULL || ethernet == NULL) {
        fastpath_log_error("vlan_set_ethernet: invalid vlan %p ethernet %p\n", 
            vlan, ethernet);

        return -EINVAL;
    }
    
    private = (struct vlan_private *)vlan->private;
    private->ethernet_dev = ethernet;

    return 0;
}

int vlan_set_bridge(struct net_device *vlan, struct net_device *br)
{
    struct vlan_private *private;

    if (vlan == NULL || br == NULL) {
        fastpath_log_error("vlan_set_bridge: invalid vlan %p bridge %p\n", 
            vlan, br);

        return -EINVAL;
    }
    
    private = (struct vlan_private *)vlan->private;
    private->bridge_dev = br;

    return 0;
}

int vlan_init(uint16_t port, uint16_t vid)
{
    struct net_device *dev;
    struct vlan_private *private;
    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("vlan_init: invalid port %d\n", port);
        return -1;
    }

    dev = rte_zmalloc(NULL, sizeof(struct net_device), 0);
    if (dev == NULL) {
        fastpath_log_error("vlan_init: malloc net_device failed\n");
        return -ENOMEM;
    }

    private = rte_zmalloc(NULL, sizeof(struct vlan_private), 0);
    if (private == NULL) {
        rte_free(dev);
        
        fastpath_log_error("vlan_init: malloc net_device failed\n");
        return -ENOMEM;
    }

    dev->ifindex = 0;
    dev->type = NET_DEVICE_TYPE_VLAN;
    snprintf(dev->name, sizeof(dev->name), "vlan%d", vid);
    
    private->port = port;
    private->vid = vid;
    
    dev->private = (void *)private;

    vlan_dev[port] = dev;

    return 0;
}


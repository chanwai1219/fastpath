
#include "fastpath.h"

struct ethernet_private {
    uint16_t port;
    uint16_t mode;
    uint16_t native;
    uint16_t reserved;
    struct net_device *vlan_dev[VLAN_VID_MAX];
    struct net_device *bridge_dev;
};

struct net_device *ethernet_dev[FASTPATH_MAX_NIC_PORTS];

static struct net_device * find_ethernet_dev(uint32_t port);

static struct net_device * find_ethernet_dev(uint32_t port)
{    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("find_ethernet_dev: invalid port %d\n", port);
        return NULL;
    }
    
    return ethernet_dev[port];
}

void ethernet_input(struct rte_mbuf *m)
{
    struct net_device *dev;

    dev = find_ethernet_dev(m->port);
    if (dev == NULL) {
        fastpath_log_error("ethernet_receive: port %d not initialized\n", m->port);

        rte_pktmbuf_free(m);
        return;
    }

    ethernet_receive(m, NULL, dev);

    return;
}

void ethernet_receive(struct rte_mbuf *m, __rte_unused struct net_device *peer, struct net_device *dev)
{
    uint32_t vid;
    struct ether_hdr *eth;
    struct vlan_hdr  *vlan_hdr;
    struct ethernet_private *private = (struct ethernet_private *)dev->private;

    fastpath_log_debug("ethernet %s receive packet\n", dev->name);

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct ether_hdr));
    vlan_hdr = rte_pktmbuf_mtod(m, struct vlan_hdr *);

    if (ntohs(eth->ether_type) == ETHER_TYPE_VLAN) {
        vid = ntohs(vlan_hdr->vlan_tci);
        
        if (private->mode == VLAN_MODE_ACCESS) {
            fastpath_log_error("access vlan %s receive packet vid %x, drop\n", 
                dev->name, vid);
            rte_pktmbuf_free(m);
            return;
        } else {
            fastpath_log_debug("trunk vlan %s receive packet vid %x\n", dev->name, vid);

            SEND_PKT(m, dev, private->vlan_dev[vid]);
        }
    } else {
        if (private->mode == VLAN_MODE_ACCESS) {
            fastpath_log_debug("access vlan %s receive untagged packet, send to %d\n",
                dev->name, private->native);
        } else {
            fastpath_log_debug("trunk vlan %s receive untagged packet, send to %d\n",
                dev->name, private->native);
        }
        SEND_PKT(m, dev, private->bridge_dev);
    }

    return;
}

void ethernet_xmit(struct rte_mbuf *m, __rte_unused struct net_device *peer, struct net_device *dev)
{
    uint32_t n_mbufs, n_pkts, port;
    unsigned lcore = rte_lcore_id();
    struct ethernet_private *private = (struct ethernet_private *)dev->private;
    struct fastpath_params_worker *lp = &fastpath.lcore_params[lcore].worker;

    port = private->port;

    fastpath_log_debug("ethernet %s prepare to send packet to port %d %d\n",
        dev->name, port, lp->tx_queue_id[port]);

    n_mbufs = lp->mbuf_out[port].n_mbufs;
    lp->mbuf_out[port].array[n_mbufs] = m;
    n_mbufs += 1;

    if (n_mbufs < fastpath.burst_size_worker_write) {
        lp->mbuf_out[port].n_mbufs = n_mbufs;
    } else {
        n_pkts = rte_eth_tx_burst(
				port,
				lp->tx_queue_id[port],
				lp->mbuf_out[port].array,
				(uint16_t) n_mbufs);

        if (unlikely(n_pkts < n_mbufs)) {
			uint32_t k;
			for (k = n_pkts; k < n_mbufs; k ++) {
				struct rte_mbuf *pkt_to_free = lp->mbuf_out[port].array[k];
				rte_pktmbuf_free(pkt_to_free);
			}
		}
        
		lp->mbuf_out[port].n_mbufs = 0;
		lp->mbuf_out_flush[port] = 0;
    }

    return;
}

int ethernet_set_vlan(struct net_device *ethernet, uint16_t vid, struct net_device *vlan)
{
    struct ethernet_private *private;

    if (vlan == NULL || ethernet == NULL) {
        fastpath_log_error("ethernet_set_vlan: invalid ethernet %p vlan %p\n", 
            ethernet, vlan);
        return -EINVAL;
    }

    if (vid > VLAN_VID_MASK) {
        fastpath_log_error("ethernet_set_vlan: invalid vid %d\n", vid);
        return -EINVAL;
    }

    private = ethernet->private;
    private->vlan_dev[vid] = vlan;

    return 0;
}

int ethernet_init(uint32_t port, uint16_t mode, uint16_t native)
{
    struct net_device *dev;
    struct ethernet_private *private;
    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("ethernet_init: invalid port %d\n", port);
        return -EINVAL;
    }

    if (ethernet_dev[port] != NULL) {
        fastpath_log_error("ethernet_init: port %d already initialized\n", port);
        return -EINVAL;
    }

    dev = rte_zmalloc(NULL, sizeof(struct net_device), 0);
    if (dev == NULL) {
        fastpath_log_error("ethernet_init: malloc net_device failed\n");
        return -ENOMEM;
    }

    private = rte_zmalloc(NULL, sizeof(struct ethernet_private), 0);
    if (private == NULL) {
        rte_free(dev);
        
        fastpath_log_error("ethernet_init: malloc net_device failed\n");
        return -ENOMEM;
    }

    dev->ifindex = 0;
    dev->type = NET_DEVICE_TYPE_ETHERNET;
    snprintf(dev->name, sizeof(dev->name), "vEth%d", port);

    private->port = port;
    private->mode = mode;
    private->native = native;
    
    dev->private = (void *)private;

    ethernet_dev[port] = dev;

    return 0;
}

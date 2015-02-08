
#include "fastpath.h"

struct net_device *ethernet_dev[FASTPATH_MAX_NIC_PORTS];

typedef struct ethernet_private {
    uint32_t port;
    net_device *vlan_dev;
};

struct net_device * find_ethernet_dev(uint32_t port)
{
    struct net_device *dev;
    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("find_ethernet_dev: invalid port %d\n", port);
        return NULL;
    }
    
    return ethernet_dev[port];
}

int ethernet_input(struct rte_mbuf *m)
{
    struct net_device *dev;

    dev = find_ethernet_dev(m->port);
    if (dev == NULL) {
        fastpath_log_error("ethernet_receive: port %d not initialized\n", m->port);

        rte_pktmbuf_free(m);
        return 0;
    }

    return ethernet_receive(m, dev);
}


int ethernet_receive(struct rte_mbuf *m, struct net_device *dev)
{
    struct ethernet_private *private;

    SEND_PKT(m, private->vlan_dev);

    return 0;
}

int ethernet_xmit(struct rte_mbuf *m, struct net_device *dev)
{
    uint32_t n_mbufs, n_pkts;
    unsigned lcore = rte_lcore_id();
    struct fastpath_params_worker *lp = app.lcore_params[lcore].worker;

    n_mbufs = lp->mbuf_out[port].n_mbufs;

    lp->mbuf_out[port].array[n_mbufs] = m;
    n_mbufs += 1;

    if (n_mbufs < app.burst_size_worker_write) {
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

    return 0;
}

int ethernet_set_vlan(struct net_device *ethernet, struct net_device *vlan)
{
    struct ethernet_private *private;

    if (vlan == NULL || ethernet == NULL) {
        fastpath_log_error("ethernet_set_vlan: invalid ethernet %p vlan %p\n", 
            ethernet, vlan);

        return -1;
    }

    private = ethernet->private;
    private->vlan_dev = vlan;

    return 0;
}

int ethernet_init(uint32_t port)
{
    struct net_device *dev;
    struct ethernet_private *private;
    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("ethernet_init: invalid port %d\n", port);
        return -1;
    }

    if (ethernet_dev[port] != NULL) {
        fastpath_log_error("ethernet_init: port %d already initialized\n", port);
        return -1;
    }

    dev = rte_malloc(NULL, sizeof(struct net_device), 0);
    if (dev == NULL) {
        fastpath_log_error("ethernet_init: malloc net_device failed\n");
        return -1;
    }

    private = rte_malloc(NULL, sizeof(struct ethernet_private), 0);
    if (private == NULL) {
        rte_free(dev);
        
        fastpath_log_error("ethernet_init: malloc net_device failed\n");
        return -1;
    }

    dev->ifindex = 0;
    snprintf(dev->name, IFNAMSIZ, "vEth%d", port);

    private->port = port;
    
    dev->private = (void *)private;

    ethernet_dev[port] = dev;

    return 0;
}

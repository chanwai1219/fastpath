
#include "fastpath.h"

struct ethernet_private {
    uint16_t port;
    uint16_t mode;
    uint16_t native;
    uint16_t reserved;
    struct module *vlan[VLAN_VID_MAX];
    struct module *bridge;
};

struct module *ethernet_modules[FASTPATH_MAX_NIC_PORTS];

static struct module * find_ethernet(uint32_t port);

static struct module * find_ethernet(uint32_t port)
{    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("find_ethernet: invalid port %d\n", port);
        return NULL;
    }
    
    return ethernet_modules[port];
}

void ethernet_input(struct rte_mbuf *m)
{
    struct module *eth;

    eth = find_ethernet(m->port);
    if (eth == NULL) {
        fastpath_log_error("ethernet_receive: port %d not initialized\n", m->port);

        rte_pktmbuf_free(m);
        return;
    }

    ethernet_receive(m, NULL, eth);

    return;
}

void ethernet_receive(struct rte_mbuf *m, __rte_unused struct module *peer, struct module *eth)
{
    uint32_t vid;
    struct ether_hdr *eth_hdr;
    struct vlan_hdr  *vlan_hdr;
    struct ethernet_private *private = (struct ethernet_private *)eth->private;

    fastpath_log_debug("ethernet %s receive packet\n", eth->name);

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct ether_hdr));
    vlan_hdr = rte_pktmbuf_mtod(m, struct vlan_hdr *);

    if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_VLAN) {
        vid = ntohs(vlan_hdr->vlan_tci);
        
        if (private->mode == VLAN_MODE_ACCESS) {
            fastpath_log_error("access vlan %s receive packet vid %x, drop\n", 
                eth->name, vid);
            rte_pktmbuf_free(m);
            return;
        } else {
            fastpath_log_debug("trunk vlan %s receive packet vid %x\n", eth->name, vid);

            SEND_PKT(m, eth, private->vlan[vid]);
        }
    } else {
        if (private->mode == VLAN_MODE_ACCESS) {
            fastpath_log_debug("access vlan %s receive untagged packet, send to %d\n",
                eth->name, private->native);
        } else {
            fastpath_log_debug("trunk vlan %s receive untagged packet, send to %d\n",
                eth->name, private->native);
        }
        SEND_PKT(m, eth, private->bridge);
    }

    return;
}

void ethernet_xmit(struct rte_mbuf *m, __rte_unused struct module *peer, struct module *eth)
{
    uint32_t n_mbufs, n_pkts, port;
    unsigned lcore = rte_lcore_id();
    struct ethernet_private *private = (struct ethernet_private *)eth->private;
    struct fastpath_params_worker *lp = &fastpath.lcore_params[lcore].worker;

    port = private->port;

    fastpath_log_debug("ethernet %s prepare to send packet to port %d %d\n",
        eth->name, port, lp->tx_queue_id[port]);

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

int ethernet_set_vlan(struct module *ethernet, uint16_t vid, struct module *vlan)
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
    private->vlan[vid] = vlan;

    return 0;
}

int ethernet_init(uint32_t port, uint16_t mode, uint16_t native)
{
    struct module *eth;
    struct ethernet_private *private;
    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("ethernet_init: invalid port %d\n", port);
        return -EINVAL;
    }

    if (ethernet_modules[port] != NULL) {
        fastpath_log_error("ethernet_init: port %d already initialized\n", port);
        return -EINVAL;
    }

    eth = rte_zmalloc(NULL, sizeof(struct module), 0);
    if (eth == NULL) {
        fastpath_log_error("ethernet_init: malloc module failed\n");
        return -ENOMEM;
    }

    private = rte_zmalloc(NULL, sizeof(struct ethernet_private), 0);
    if (private == NULL) {
        rte_free(eth);
        
        fastpath_log_error("ethernet_init: malloc module failed\n");
        return -ENOMEM;
    }

    eth->ifindex = 0;
    eth->type = MODULE_TYPE_ETHERNET;
    snprintf(eth->name, sizeof(eth->name), "vEth%d", port);

    private->port = port;
    private->mode = mode;
    private->native = native;
    
    eth->private = (void *)private;

    ethernet_modules[port] = eth;

    return 0;
}

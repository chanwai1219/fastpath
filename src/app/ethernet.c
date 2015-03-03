
#include "fastpath.h"

struct ethernet_private {
    uint16_t port;
    uint16_t mode;
    uint16_t native;
    uint16_t state;
    struct module *vlan[VLAN_VID_MAX];
    struct module *bridge;
};

struct module *ethernet_modules[FASTPATH_MAX_NIC_PORTS];

static struct module * find_ethernet(uint32_t port);
static uint64_t flowkey_hash(
    void *key,
    __attribute__((unused)) uint32_t key_size,
    __attribute__((unused)) uint64_t seed);

static struct module * find_ethernet(uint32_t port)
{    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("find_ethernet: invalid port %d\n", port);
        return NULL;
    }
    
    return ethernet_modules[port];
}

uint64_t flowkey_hash(
    void *key,
    __attribute__((unused)) uint32_t key_size,
    __attribute__((unused)) uint64_t seed)
{
    struct fastpath_flow_key *flow_key = (struct fastpath_flow_key *) key;
    uint32_t ip_dst = rte_be_to_cpu_32(flow_key->ip_dst);
    uint64_t signature = (ip_dst & 0x00FFFFFFLLU) >> 2;

    return signature;
}

static inline void
fastpath_pkt_metadata_fill(struct rte_mbuf *m)
{
    struct fastpath_pkt_metadata *c =
        (struct fastpath_pkt_metadata *)RTE_MBUF_METADATA_UINT8_PTR(m, 0);
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    uint64_t *ipv4_hdr_slab;

#if 0
    uint8_t *m_data = rte_pktmbuf_mtod(m, uint8_t *);

    if (m->ol_flags & (PKT_RX_VLAN_PKT)) {
        ip_hdr = (struct ipv4_hdr *) 
            &m_data[sizeof(struct ether_hdr) + sizeof(struct vlan_hdr)];
    } else {
        ip_hdr = (struct ipv4_hdr *) &m_data[sizeof(struct ether_hdr)];
    }
#endif

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr*);

    c->mac_header = (uint8_t *)eth_hdr;
    c->protocol = rte_be_to_cpu_16(eth_hdr->ether_type);

    if (c->protocol == ETHER_TYPE_VLAN) {
        ip_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct vlan_hdr));
    } else {
        ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
    }
    
    ipv4_hdr_slab = (uint64_t *)ip_hdr;
    
    /* TTL and Header Checksum are set to 0 */
    c->flow_key.slab0 = ipv4_hdr_slab[1] & 0xFFFFFFFF0000FF00LLU;
    c->flow_key.slab1 = ipv4_hdr_slab[2];
    c->signature = flowkey_hash((void *) &c->flow_key, 0, 0);
}

void ethernet_input(struct rte_mbuf *m)
{
    struct module *eth;
    struct fastpath_pkt_metadata *c =
        (struct fastpath_pkt_metadata *)RTE_MBUF_METADATA_UINT8_PTR(m, 0);

    eth = find_ethernet(m->port);
    if (eth == NULL) {
        fastpath_log_error("ethernet_input: port %d not initialized\n", m->port);

        rte_pktmbuf_free(m);
        return;
    }

    fastpath_pkt_metadata_fill(m);

    if (c->protocol == ETHER_TYPE_ARP || c->protocol == ETHER_TYPE_RARP) {
        kni_ingress(m);
        return;
    }

    ethernet_receive(m, NULL, eth);

    return;
}

void ethernet_receive(struct rte_mbuf *m, struct module *peer, struct module *eth)
{
    uint32_t vid;
    struct ether_hdr *eth_hdr;
    struct vlan_hdr  *vlan_hdr;
    struct ethernet_private *private = (struct ethernet_private *)eth->private;

    RTE_SET_USED(peer);

    fastpath_log_debug("lcore %d ethernet %s receive packet segments %d length %d\n", 
        rte_lcore_id(), eth->name, m->nb_segs, m->pkt_len);

#if 0
    rte_pktmbuf_dump(stdout, m, 128);
#endif

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct ether_hdr));

    if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_VLAN) {
        vlan_hdr = rte_pktmbuf_mtod(m, struct vlan_hdr *);
        
        vid = ntohs(vlan_hdr->vlan_tci);
        
        if (private->mode == VLAN_MODE_ACCESS) {
            fastpath_log_error("access port %s receive packet vid %x, drop\n", 
                eth->name, vid);
            rte_pktmbuf_free(m);
            return;
        } else {
            fastpath_log_debug("trunk port %s receive packet vid %x\n", eth->name, vid);

            SEND_PKT(m, eth, private->vlan[vid], PKT_DIR_RECV);
        }
    } else {
        if (private->mode == VLAN_MODE_ACCESS) {
            fastpath_log_debug("access port %s receive untagged packet, send to %d\n",
                eth->name, private->native);
        } else {
            fastpath_log_debug("trunk port %s receive untagged packet, send to %d\n",
                eth->name, private->native);
        }
        SEND_PKT(m, eth, private->bridge, PKT_DIR_RECV);
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

    fastpath_log_debug("ethernet %s prepare to send packet to port %d %d pkt len %d\n",
        eth->name, port, lp->tx_queue_id[port], m->pkt_len);

    if (private->state == 0) {
        fastpath_log_debug("ethernet %s link down\n", eth->name);
        rte_pktmbuf_free(m);
        return;
    }

#if 0
    rte_pktmbuf_dump(stdout, m, 128);
#endif

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
            fastpath_log_error("ethernet_xmit: send pkt failed, success %d expected %d",
                n_pkts, n_mbufs);
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

int ethernet_handle_msg(struct module *eth, 
    struct msg_hdr *req, struct msg_hdr *resp)
{
    int ret = 0;
    struct ethernet_private *private;

    if (eth == NULL) {
        fastpath_log_error("ethernet_handle_msg: invalid local ptr\n");
        return -EINVAL;
    }

    private = (struct ethernet_private *)eth->private;

    switch (req->cmd) {
    case ETHERNET_GET_ADDRESS:
        rte_eth_macaddr_get(private->port, (struct ether_addr *)resp->data);
        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

int ethernet_connect(struct module *local, struct module *peer, void *param)
{
    struct ethernet_private *private;

    if (local == NULL || peer == NULL) {
        fastpath_log_error("ethernet_connect: invalid local %p peer %p\n", 
            local, peer);
        return -EINVAL;
    }
    
    fastpath_log_info("ethernet_connect: local %s peer %s\n", local->name, peer->name);

    private = local->private;
    
    if (peer->type == MODULE_TYPE_VLAN) {
        uint16_t vid = *(uint16_t *)param;
        if (vid > VLAN_VID_MASK) {
            fastpath_log_error("ethernet_connect: invalid vid %d\n", vid);
            return -EINVAL;
        }

        private->vlan[vid] = peer;
    } else if (peer->type == MODULE_TYPE_BRIDGE) {
        private->bridge = peer;
    } else {
        fastpath_log_error("ethernet_connect: invalid peer type %d\n", peer->type);
        return -ENOENT;
    }

    return 0;
}

struct module * ethernet_init(uint32_t port, uint16_t mode, uint16_t native)
{
    struct module *eth;
    struct ethernet_private *private;
    struct rte_eth_link link;
    
    if (port >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("ethernet_init: invalid port %d\n", port);
        return NULL;
    }

    if (ethernet_modules[port] != NULL) {
        fastpath_log_error("ethernet_init: port %d already initialized\n", port);
        return NULL;
    }

    eth = rte_zmalloc(NULL, sizeof(struct module), 0);
    if (eth == NULL) {
        fastpath_log_error("ethernet_init: malloc module failed\n");
        return NULL;
    }

    private = rte_zmalloc(NULL, sizeof(struct ethernet_private), 0);
    if (private == NULL) {
        rte_free(eth);
        
        fastpath_log_error("ethernet_init: malloc module failed\n");
        return NULL;
    }

    eth->receive = ethernet_receive;
    eth->transmit = ethernet_xmit;
    eth->connect = ethernet_connect;
    eth->message = ethernet_handle_msg;
    eth->type = MODULE_TYPE_ETHERNET;
    snprintf(eth->name, sizeof(eth->name), "vEth%d", port);

    private->port = port;
    private->mode = mode;
    private->native = native;

    rte_eth_link_get_nowait(port, &link);
    
    private->state = link.link_status;
    
    eth->private = (void *)private;

    ethernet_modules[port] = eth;

    fastpath_log_info("ethernet_init: port %d mode %d native %d link %d\n", 
        port, mode, native, link.link_status);

    return eth;
}

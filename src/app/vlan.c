
#include "fastpath.h"
#include "vlan.h"

struct vlan_private {
    uint16_t vid;
    uint16_t reserved;
    struct module *ethernet;
    struct module *bridge;
};

struct module *vlan_modules[VLAN_VID_MAX];

void vlan_receive(struct rte_mbuf *m, __rte_unused struct module *peer, struct module *vlan)
{
    struct vlan_private *private = (struct vlan_private *)vlan->private;

    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct vlan_hdr));
#if 0
    memmove(rte_pktmbuf_mtod(m, char *) - sizeof(struct ether_hdr), 
        rte_pktmbuf_mtod(m, char *) - sizeof(struct ether_hdr) - sizeof(struct vlan_hdr), 
        2 * sizeof(struct ether_addr));
#endif

    SEND_PKT(m, vlan, private->bridge, PKT_DIR_RECV);
    
    return;
}

void vlan_xmit(struct rte_mbuf *m, __rte_unused struct module *peer, struct module *vlan)
{
    struct ether_hdr *eth_hdr;
    struct vlan_hdr  *vlan_hdr;
    struct vlan_private *private = (struct vlan_private *)vlan->private;

    fastpath_log_debug("vlan %s add 8021q tag %d to packet\n", vlan->name, private->vid);
    
    rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct vlan_hdr));
    memmove(rte_pktmbuf_mtod(m, void *), 
        rte_pktmbuf_mtod(m, char *) + sizeof(struct vlan_hdr), 
        2 * sizeof(struct ether_addr));
    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);
    vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);
    vlan_hdr->vlan_tci = rte_cpu_to_be_16(private->vid);
    
    SEND_PKT(m, vlan, private->ethernet, PKT_DIR_XMIT);
    
    return;
}

int vlan_connect(struct module *local, struct module *peer, void *param)
{
    struct vlan_private *private;
    RTE_SET_USED(param);

    if (local == NULL || peer == NULL) {
        fastpath_log_error("vlan_connect: invalid local %p peer %p\n", 
            local, peer);
        return -EINVAL;
    }
    
    fastpath_log_info("vlan_connect: local %s peer %s\n", local->name, peer->name);

    private = (struct vlan_private *)local->private;

    if (peer->type == MODULE_TYPE_BRIDGE) {
        private->bridge = peer;
    } else if (peer->type == MODULE_TYPE_ETHERNET) {
        uint16_t vid = *(uint16_t *)param;
        private->ethernet = peer;

        peer->connect(peer, local, &vid);
    } else {
        fastpath_log_error("vlan_connect: invalid peer type %d\n", peer->type);
        return -ENOENT;
    }

    return 0;
}

struct module* vlan_init(uint16_t port, uint16_t vid)
{
    struct module *vlan;
    struct vlan_private *private;

    if (vid > VLAN_VID_MASK) {
        fastpath_log_error("vlan_init: invalid vid %d\n", vid);
        return NULL;
    }

    fastpath_log_info("vlan_init: vlan %d\n", vid);
    
    vlan = rte_zmalloc(NULL, sizeof(struct module), 0);
    if (vlan == NULL) {
        fastpath_log_error("vlan_init: malloc module failed\n");
        return NULL;
    }

    private = rte_zmalloc(NULL, sizeof(struct vlan_private), 0);
    if (private == NULL) {
        rte_free(vlan);
        
        fastpath_log_error("vlan_init: malloc module failed\n");
        return NULL;
    }

    vlan->receive = vlan_receive;
    vlan->transmit = vlan_xmit;
    vlan->connect = vlan_connect;
    vlan->type = MODULE_TYPE_VLAN;
    snprintf(vlan->name, sizeof(vlan->name), "vEth%d.%d", port, vid);
    
    private->vid = vid;
    
    vlan->private = (void *)private;

    vlan_modules[vid] = vlan;

    return vlan;
}



#ifndef __ETHERNET_H__
#define __ETHERNET_H__

enum {
    VLAN_MODE_ACCESS,
    VLAN_MODE_TRUNK
};

void ethernet_input(struct rte_mbuf *m);
void ethernet_receive(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev);
void ethernet_xmit(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev);
int ethernet_set_vlan(struct net_device *ethernet, uint16_t vid, struct net_device *vlan);
int ethernet_init(uint32_t port, uint16_t mode, uint16_t native);

#endif


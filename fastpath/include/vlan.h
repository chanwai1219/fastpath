
#ifndef __VLAN_H__
#define __VLAN_H__

#define VLAN_VID_MAX    4096
#define VLAN_VID_MASK	0xFFF

void vlan_receive(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev);
void vlan_xmit(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev);
int vlan_set_ethernet(struct net_device *vlan, struct net_device *ethernet);
int vlan_set_bridge(struct net_device *vlan, struct net_device *br);
int vlan_init(uint16_t port, uint16_t vid);

#endif


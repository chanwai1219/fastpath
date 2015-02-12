
#ifndef __VLAN_H__
#define __VLAN_H__

#define VLAN_VID_MAX    4096
#define VLAN_VID_MASK	0xFFF

void vlan_receive(struct rte_mbuf *m, struct module *peer, struct module *vlan);
void vlan_xmit(struct rte_mbuf *m, struct module *peer, struct module *vlan);
int vlan_set_ethernet(struct module *vlan, struct module *ethernet);
int vlan_set_bridge(struct module *vlan, struct module *br);
int vlan_init(uint16_t vid);

#endif

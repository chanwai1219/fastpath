
#ifndef __ETHERNET_H__
#define __ETHERNET_H__

enum {
    VLAN_MODE_ACCESS,
    VLAN_MODE_TRUNK
};

void ethernet_input(struct rte_mbuf *m);
void ethernet_receive(struct rte_mbuf *m, struct module *peer, struct module *eth);
void ethernet_xmit(struct rte_mbuf *m, struct module *peer, struct module *eth);
int ethernet_set_vlan(struct module *ethernet, uint16_t vid, struct module *vlan);
int ethernet_init(uint32_t port, uint16_t mode, uint16_t native);

#endif


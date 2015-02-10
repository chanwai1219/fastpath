
#ifndef __BRIDGE_H__
#define __BRIDGE_H__

void bridge_receive(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev);
void bridge_xmit(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev);
int bridge_init(uint16_t vid);
int bridge_fini(void);

#endif


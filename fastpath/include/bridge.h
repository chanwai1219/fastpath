
#ifndef __BRIDGE_H__
#define __BRIDGE_H__

void bridge_receive(struct rte_mbuf *m, struct module *peer, struct module *br);
void bridge_xmit(struct rte_mbuf *m, struct module *peer, struct module *br);
int bridge_connect(struct module *local, struct module *peer, void *param);
struct module * bridge_init(uint16_t vid);
int bridge_fini(void);

#endif


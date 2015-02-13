
#ifndef __INTERFACE_H__
#define __INTERFACE_H__

void interface_receive(struct rte_mbuf *m, struct module *peer, struct module *dev);
void interface_xmit(struct rte_mbuf *m, struct module *peer, struct module *dev);
int interface_connect(struct module *local, struct module *peer, void *param);
struct module * interface_init(uint16_t ifidx);

#endif


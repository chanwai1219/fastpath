
#ifndef __INTERFACE_H__
#define __INTERFACE_H__

void interface_receive(struct rte_mbuf *m, 
    __rte_unused struct module *peer, struct module *dev);
void interface_xmit(struct rte_mbuf *m, 
    __rte_unused struct module *peer, struct module *dev);
int interface_init(uint16_t ifidx);

#endif


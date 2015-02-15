
#ifndef __ROUTE_H__
#define __ROUTE_H__

#define ROUTE_MAX_LINK  16

void route_receive(struct rte_mbuf *m, struct module *peer, struct module *ipfwd);
void route_xmit(struct rte_mbuf *m, struct module *peer, struct module *ipfwd);
int route_connect(struct module *local, struct module *peer, void *param);
struct module * route_init(void);

#endif


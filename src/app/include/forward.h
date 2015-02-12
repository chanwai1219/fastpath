
#ifndef __FORWARD_H__
#define __FORWARD_H__

void ipfwd_receive(struct rte_mbuf *m, struct module *peer, struct module *ipfwd);
void ipfwd_xmit(struct rte_mbuf *m, struct module *peer, struct module *ipfwd);
int ipfwd_init(void);


#endif


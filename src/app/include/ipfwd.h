
#ifndef __FORWARD_H__
#define __FORWARD_H__

#define IPFWD_MAX_LINK  16

void ipfwd_receive(struct rte_mbuf *m, struct module *peer, struct module *ipfwd);
void ipfwd_xmit(struct rte_mbuf *m, struct module *peer, struct module *ipfwd);
int ipfwd_connect(struct module *local, struct module *peer, void *param);
struct module * ipfwd_init(void);


#endif


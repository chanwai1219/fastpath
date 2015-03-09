
#ifndef __TCM_H__
#define __TCM_H__

void tcm_receive(struct rte_mbuf *m, struct module *peer, struct module *tcm);
void tcm_xmit(struct rte_mbuf *m, struct module *peer, struct module *tcm);
int tcm_handle_msg(struct module *route, 
    struct msg_hdr *req, struct msg_hdr *resp);
int tcm_connect(struct module *local, struct module *peer, void *param);
struct module * tcm_init(uint16_t index, uint16_t mode);

#endif


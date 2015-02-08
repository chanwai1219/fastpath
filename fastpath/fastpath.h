
#ifndef __FASTPATH_H__
#define __FASTPATH_H__

#include "main.h"
#include "netdevice.h"

#define SEND_PKT(m, peer) do { \
        if (unlikely((peer) == NULL)) { \
            fastpath_log_error("%s: peer not valid\n", __func__); \
            rte_pktmbuf_free((m)); \
        } else { \
            if (unlikely((peer)->receive == NULL)) { \
                fastpath_log_error("%s: peer receive not valid\n", __func__); \
                rte_pktmbuf_free((m)); \
            } else { \
                (peer)->receive((m), (peer)); \
            } \
        } \
    } while (0)

#endif /* __FASTPATH_H__ */


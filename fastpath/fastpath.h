
#ifndef __FASTPATH_H__
#define __FASTPATH_H__

#include "main.h"
#include "netdevice.h"

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]

#define SEND_PKT(m, local, peer) do { \
        if (unlikely((peer) == NULL)) { \
            fastpath_log_error("%s: peer not valid\n", __func__); \
            rte_pktmbuf_free((m)); \
        } else { \
            if (unlikely((peer)->receive == NULL)) { \
                fastpath_log_error("%s: peer receive not valid\n", __func__); \
                rte_pktmbuf_free((m)); \
            } else { \
                (peer)->receive((m), (local), (peer)); \
            } \
        } \
    } while (0)

#endif /* __FASTPATH_H__ */


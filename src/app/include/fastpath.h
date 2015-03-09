
#ifndef __FASTPATH_H__
#define __FASTPATH_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <assert.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_port.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip_frag.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_rwlock.h>
#include <rte_kni.h>
#include <rte_meter.h>

#include "libxml/list.h"
#include "libxml/parser.h"
#include "libxml/tree.h"
#include "libxml/xpath.h"

#include "thread.h"

#include "manager.h"
#include "main.h"
#include "log.h"
#include "utils.h"
#include "stack.h"

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((uint8_t*)(x))[0],((uint8_t*)(x))[1],((uint8_t*)(x))[2], \
    ((uint8_t*)(x))[3],((uint8_t*)(x))[4],((uint8_t*)(x))[5]

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

#define NIP6(addr) \
    ntohs((addr)[0]), \
    ntohs((addr)[1]), \
    ntohs((addr)[2]), \
    ntohs((addr)[3]), \
    ntohs((addr)[4]), \
    ntohs((addr)[5]), \
    ntohs((addr)[6]), \
    ntohs((addr)[7])
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define NIP6_SEQFMT "%04x%04x%04x%04x%04x%04x%04x%04x"

#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr) \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD     NIPQUAD
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */

enum {
    MODULE_TYPE_ETHERNET,
    MODULE_TYPE_VLAN,
    MODULE_TYPE_BRIDGE,
    MODULE_TYPE_INTERFACE,
    MODULE_TYPE_ACL,
    MODULE_TYPE_TCM,
    MODULE_TYPE_ROUTE,
};

#define FASTPATH_MSG_FAILED     0xFF

struct msg_hdr {
    char path[32];
    uint8_t flag;
    uint8_t cmd;
    uint16_t len;
    uint8_t data[0];
};

struct module {
#define NAME_SIZE   16
    char name[NAME_SIZE];
    uint16_t type;
    int (*connect)(struct module *local, struct module *peer, void *param);
    int (*message)(struct module *local, struct msg_hdr *req, struct msg_hdr *resp);
    void (*receive)(struct rte_mbuf *m, struct module *peer, struct module *local);
    void (*transmit)(struct rte_mbuf *m, struct module *peer, struct module *local);
    void *private;
};

enum {
    PKT_DIR_RECV,
    PKT_DIR_XMIT,
};

#define SEND_PKT(m, local, peer, dir) do { \
        if (unlikely((peer) == NULL)) { \
            fastpath_log_error("%s: local %s peer not valid\n", __func__, local->name); \
            rte_pktmbuf_free((m)); \
        } else { \
            if (dir == PKT_DIR_RECV) { \
                if (unlikely((peer)->receive == NULL)) { \
                    fastpath_log_error("%s: local %s peer receive not valid\n", __func__, local->name); \
                    rte_pktmbuf_free((m)); \
                } else { \
                    (peer)->receive((m), (local), (peer)); \
                } \
            } else { \
                if (unlikely((peer)->transmit == NULL)) { \
                    fastpath_log_error("%s: local %s peer transmit not valid\n", __func__, local->name); \
                    rte_pktmbuf_free((m)); \
                } else { \
                    (peer)->transmit((m), (local), (peer)); \
                } \
            }\
        } \
    } while (0)

struct fastpath_flow_key {
    union {
        struct {
            uint8_t ttl; /* needs to be set to 0 */
            uint8_t proto;
            uint16_t header_checksum; /* needs to be set to 0 */
            uint32_t ip_src;
        };
        uint64_t slab0;
    };

    union {
        struct {
            uint32_t ip_dst;
            uint16_t port_src;
            uint16_t port_dst;
        };
        uint64_t slab1;
    };
} __attribute__((__packed__));

struct fastpath_arp_key {
    uint32_t nh_ip;
    uint32_t nh_iface;
} __attribute__((__packed__));

struct fastpath_pkt_metadata {
    uint32_t signature;
    uint16_t protocol;
    uint8_t reserved1[10];

    uint8_t *mac_header;
    uint8_t *network_header;

    struct fastpath_flow_key flow_key;

    struct fastpath_arp_key arp_key;
    struct ether_addr nh_arp;

    uint8_t reserved3[2];
} __attribute__((__packed__));

#include "ethernet.h"
#include "vlan.h"
#include "bridge.h"
#include "interface.h"
#include "tcm.h"
#include "route.h"

#endif /* __FASTPATH_H__ */


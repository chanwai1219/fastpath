/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MAIN_H_
#define _MAIN_H_

/* Logical cores */
#ifndef FASTPATH_MAX_SOCKETS
#define FASTPATH_MAX_SOCKETS 2
#endif

#ifndef FASTPATH_MAX_LCORES
#define FASTPATH_MAX_LCORES RTE_MAX_LCORE
#endif

#ifndef FASTPATH_MAX_NIC_PORTS
#define FASTPATH_MAX_NIC_PORTS RTE_MAX_ETHPORTS
#endif

#ifndef FASTPATH_MAX_RX_QUEUES_PER_NIC_PORT
#define FASTPATH_MAX_RX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef FASTPATH_MAX_TX_QUEUES_PER_NIC_PORT
#define FASTPATH_MAX_TX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef FASTPATH_MAX_RX_LCORES
#define FASTPATH_MAX_RX_LCORES 16
#endif
#if (FASTPATH_MAX_RX_LCORES > FASTPATH_MAX_LCORES)
#error "FASTPATH_MAX_RX_LCORES is too big"
#endif

#ifndef FASTPATH_MAX_NIC_RX_QUEUES_PER_LCORE
#define FASTPATH_MAX_NIC_RX_QUEUES_PER_LCORE 16
#endif

#ifndef FASTPATH_MAX_WORKER_LCORES
#define FASTPATH_MAX_WORKER_LCORES 16
#endif
#if (FASTPATH_MAX_WORKER_LCORES > FASTPATH_MAX_LCORES)
#error "FASTPATH_MAX_WORKER_LCORES is too big"
#endif


/* Mempools */
#ifndef FASTPATH_DEFAULT_MBUF_SIZE
#define FASTPATH_DEFAULT_MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#endif

#ifndef FASTPATH_DEFAULT_INDIRECT_MBUF_SIZE
#define FASTPATH_DEFAULT_INDIRECT_MBUF_SIZE (sizeof(struct rte_mbuf) + sizeof(struct fastpath_pkt_metadata))
#endif

#ifndef FASTPATH_DEFAULT_MEMPOOL_BUFFERS
#define FASTPATH_DEFAULT_MEMPOOL_BUFFERS   8192 * 4
#endif

#ifndef FASTPATH_DEFAULT_MEMPOOL_CACHE_SIZE
#define FASTPATH_DEFAULT_MEMPOOL_CACHE_SIZE  256
#endif

/* Neigh Tables */
#ifndef FASTPATH_NEIGH_HASH_ENTRIES
#define FASTPATH_NEIGH_HASH_ENTRIES 1024*1024*1
#endif 

/* LPM Tables */
#ifndef FASTPATH_MAX_LPM_RULES
#define FASTPATH_MAX_LPM_RULES (16*1024)
#endif

#ifndef FASTPATH_MAX_LPM6_RULES
#define FASTPATH_MAX_LPM6_RULES (16*1024)
#endif

#ifndef FASTPATH_LPM6_NUMBER_TBL8S
#define FASTPATH_LPM6_NUMBER_TBL8S (1 << 16)
#endif

/* NIC RX */
#ifndef FASTPATH_DEFAULT_NIC_RX_RING_SIZE
#define FASTPATH_DEFAULT_NIC_RX_RING_SIZE 1024
#endif

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#ifndef FASTPATH_DEFAULT_NIC_RX_PTHRESH
#define FASTPATH_DEFAULT_NIC_RX_PTHRESH  8
#endif

#ifndef FASTPATH_DEFAULT_NIC_RX_HTHRESH
#define FASTPATH_DEFAULT_NIC_RX_HTHRESH  8
#endif

#ifndef FASTPATH_DEFAULT_NIC_RX_WTHRESH
#define FASTPATH_DEFAULT_NIC_RX_WTHRESH  4
#endif

#ifndef FASTPATH_DEFAULT_NIC_RX_FREE_THRESH
#define FASTPATH_DEFAULT_NIC_RX_FREE_THRESH  64
#endif

#ifndef FASTPATH_DEFAULT_NIC_RX_DROP_EN
#define FASTPATH_DEFAULT_NIC_RX_DROP_EN 0
#endif

/* NIC TX */
#ifndef FASTPATH_DEFAULT_NIC_TX_RING_SIZE
#define FASTPATH_DEFAULT_NIC_TX_RING_SIZE 1024
#endif

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#ifndef FASTPATH_DEFAULT_NIC_TX_PTHRESH
#define FASTPATH_DEFAULT_NIC_TX_PTHRESH  36
#endif

#ifndef FASTPATH_DEFAULT_NIC_TX_HTHRESH
#define FASTPATH_DEFAULT_NIC_TX_HTHRESH  0
#endif

#ifndef FASTPATH_DEFAULT_NIC_TX_WTHRESH
#define FASTPATH_DEFAULT_NIC_TX_WTHRESH  0
#endif

#ifndef FASTPATH_DEFAULT_NIC_TX_FREE_THRESH
#define FASTPATH_DEFAULT_NIC_TX_FREE_THRESH  0
#endif

#ifndef FASTPATH_DEFAULT_NIC_TX_RS_THRESH
#define FASTPATH_DEFAULT_NIC_TX_RS_THRESH  0
#endif

/* Software Rings */
#ifndef FASTPATH_DEFAULT_RING_SIZE
#define FASTPATH_DEFAULT_RING_SIZE 1024
#endif

/* Bursts */
#ifndef FASTPATH_MBUF_ARRAY_SIZE
#define FASTPATH_MBUF_ARRAY_SIZE   512
#endif

#ifndef FASTPATH_DEFAULT_BURST_SIZE_RX_READ
#define FASTPATH_DEFAULT_BURST_SIZE_RX_READ  144
#endif
#if (FASTPATH_DEFAULT_BURST_SIZE_RX_READ > FASTPATH_MBUF_ARRAY_SIZE)
#error "FASTPATH_DEFAULT_BURST_SIZE_RX_READ is too big"
#endif

#ifndef FASTPATH_DEFAULT_BURST_SIZE_RX_WRITE
#define FASTPATH_DEFAULT_BURST_SIZE_RX_WRITE  144
#endif
#if (FASTPATH_DEFAULT_BURST_SIZE_RX_WRITE > FASTPATH_MBUF_ARRAY_SIZE)
#error "FASTPATH_DEFAULT_BURST_SIZE_RX_WRITE is too big"
#endif

#ifndef FASTPATH_DEFAULT_BURST_SIZE_WORKER_READ
#define FASTPATH_DEFAULT_BURST_SIZE_WORKER_READ  144
#endif
#if ((2 * FASTPATH_DEFAULT_BURST_SIZE_WORKER_READ) > FASTPATH_MBUF_ARRAY_SIZE)
#error "FASTPATH_DEFAULT_BURST_SIZE_WORKER_READ is too big"
#endif

#ifndef FASTPATH_DEFAULT_BURST_SIZE_WORKER_WRITE
#define FASTPATH_DEFAULT_BURST_SIZE_WORKER_WRITE  144
#endif
#if (FASTPATH_DEFAULT_BURST_SIZE_WORKER_WRITE > FASTPATH_MBUF_ARRAY_SIZE)
#error "FASTPATH_DEFAULT_BURST_SIZE_WORKER_WRITE is too big"
#endif

/* Load balancing logic */
#ifndef FASTPATH_DEFAULT_IO_RX_LB_POS
#define FASTPATH_DEFAULT_IO_RX_LB_POS 29
#endif
#if (FASTPATH_DEFAULT_IO_RX_LB_POS >= 64)
#error "FASTPATH_DEFAULT_IO_RX_LB_POS is too big"
#endif

#ifndef FASTPATH_DEFAULT_NUMA_ON
#define FASTPATH_DEFAULT_NUMA_ON 1
#endif

#ifndef FASTPATH_CLONE_PORTS
#define FASTPATH_CLONE_PORTS    2
#endif

#ifndef FASTPATH_CLONE_SEGS
#define FASTPATH_CLONE_SEGS     2
#endif

#ifndef IPV4_MTU_DEFAULT
#define IPV4_MTU_DEFAULT        ETHER_MTU
#endif

#ifndef IPV6_MTU_DEFAULT
#define	IPV6_MTU_DEFAULT        ETHER_MTU
#endif

#ifndef IP_FRAG_TBL_BUCKET_ENTRIES
#define IP_FRAG_TBL_BUCKET_ENTRIES    16
#endif

#define MAX_FLOW_NUM    UINT16_MAX
#define MIN_FLOW_NUM    1
#define DEF_FLOW_NUM    0x1000

/* TTL numbers are in ms. */
#define MAX_FLOW_TTL    (3600 * MS_PER_S)
#define MIN_FLOW_TTL    1
#define DEF_FLOW_TTL    MS_PER_S

#define MAX_FRAG_NUM    RTE_LIBRTE_IP_FRAG_MAX_FRAG

struct mbuf_array {
    struct rte_mbuf *array[FASTPATH_MBUF_ARRAY_SIZE];
    uint32_t n_mbufs;
};

enum fastpath_lcore_type {
    e_FASTPATH_LCORE_DISABLED = 0,
    e_FASTPATH_LCORE_RX,
    e_FASTPATH_LCORE_WORKER,
    e_FASTPATH_LCORE_RX_WORKER
};

struct fastpath_params_rx {
    /* NIC */
    struct {
        uint8_t port;
        uint8_t queue;
    } nic_queues[FASTPATH_MAX_NIC_RX_QUEUES_PER_LCORE];
    uint32_t n_nic_queues;

    /* Rings */
    struct rte_ring *rings[FASTPATH_MAX_WORKER_LCORES];
    uint32_t n_rings;

    /* Internal buffers */
    struct mbuf_array mbuf_in;
    struct mbuf_array mbuf_out[FASTPATH_MAX_WORKER_LCORES];
    uint8_t mbuf_out_flush[FASTPATH_MAX_WORKER_LCORES];

    /* Stats */
    uint32_t nic_queues_count[FASTPATH_MAX_NIC_RX_QUEUES_PER_LCORE];
    uint32_t nic_queues_iters[FASTPATH_MAX_NIC_RX_QUEUES_PER_LCORE];
    uint32_t rings_count[FASTPATH_MAX_WORKER_LCORES];
    uint32_t rings_iters[FASTPATH_MAX_WORKER_LCORES];
};

struct fastpath_params_worker {
    /* NIC */
    uint16_t tx_queue_id[FASTPATH_MAX_NIC_PORTS];
    
    /* Rings */
    struct rte_ring *rings[FASTPATH_MAX_RX_LCORES];
    uint32_t n_rings;

    /* LPM table */
    struct rte_lpm *lpm_table;
    uint32_t worker_id;

    /* Internal buffers */
    struct mbuf_array mbuf_in;
    struct mbuf_array mbuf_out[FASTPATH_MAX_NIC_PORTS];
    uint8_t mbuf_out_flush[FASTPATH_MAX_NIC_PORTS];
};

struct fastpath_lcore_params {
    struct fastpath_params_rx rx;
    struct fastpath_params_worker worker;
    enum fastpath_lcore_type type;
    struct rte_mempool *pktbuf_pool;
    struct rte_mempool *indirect_pool;
} __rte_cache_aligned;

struct fastpath_lpm_rule {
    uint32_t ip;
    uint8_t depth;
    uint8_t if_out;
};

struct fastpath_params {
    /* lcore */
    struct fastpath_lcore_params lcore_params[FASTPATH_MAX_LCORES];

    /* NIC */
    uint8_t nic_rx_queue_mask[FASTPATH_MAX_NIC_PORTS][FASTPATH_MAX_RX_QUEUES_PER_NIC_PORT];

    /* mbuf pools */
    struct rte_mempool *pktbuf_pools[FASTPATH_MAX_SOCKETS];
    struct rte_mempool *indirect_pools[FASTPATH_MAX_SOCKETS];
    struct rte_ip_frag_tbl *frag_tbl;
    struct rte_ip_frag_death_row death_row;

    /* LPM tables */
    struct rte_lpm *lpm_tables[FASTPATH_MAX_SOCKETS];
    struct fastpath_lpm_rule lpm_rules[FASTPATH_MAX_LPM_RULES];
    uint32_t n_lpm_rules;

    /* rings */
    uint32_t nic_rx_ring_size;
    uint32_t nic_tx_ring_size;
    uint32_t ring_size;

    /* burst size */
    uint32_t burst_size_rx_read;
    uint32_t burst_size_rx_write;
    uint32_t burst_size_worker_read;
    uint32_t burst_size_worker_write;

    /* load balancing */
    uint8_t pos_lb;
    uint8_t numa_on;
} __rte_cache_aligned;

extern struct fastpath_params fastpath;

int fastpath_parse_args(int argc, char **argv);
void fastpath_print_usage(void);
void fastpath_init(void);
int fastpath_main_loop(void *arg);

int fastpath_get_nic_rx_queues_per_port(uint8_t port);
int fastpath_get_nic_tx_queues_per_port(uint8_t port);
int fastpath_get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t *lcore_out);
int fastpath_get_lcore_for_nic_tx(uint8_t port, uint32_t *lcore_out);
int fastpath_is_socket_used(uint32_t socket);
uint32_t fastpath_get_lcores_rx(void);
uint32_t fastpath_get_lcores_worker(void);
uint32_t fastpath_get_lcores_rx_worker(void);
void fastpath_print_params(void);

#endif /* _MAIN_H_ */

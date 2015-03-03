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

#include "fastpath.h"

#ifndef FASTPATH_RX_FLUSH
#define FASTPATH_RX_FLUSH                   1000000
#endif

#ifndef FASTPATH_WORKER_FLUSH
#define FASTPATH_WORKER_FLUSH               1000000
#endif

#ifndef FASTPATH_STATS
#define FASTPATH_STATS                      1000000
#endif

#ifndef FASTPATH_RX_PREFETCH_ENABLE
#define FASTPATH_RX_PREFETCH_ENABLE         1
#endif

#ifndef FASTPATH_WORKER_PREFETCH_ENABLE
#define FASTPATH_WORKER_PREFETCH_ENABLE     1
#endif

#if FASTPATH_RX_PREFETCH_ENABLE
#define FASTPATH_RX_PREFETCH0(p)        rte_prefetch0(p)
#define FASTPATH_RX_PREFETCH1(p)        rte_prefetch1(p)
#else
#define FASTPATH_RX_PREFETCH0(p)
#define FASTPATH_RX_PREFETCH1(p)
#endif

#if FASTPATH_WORKER_PREFETCH_ENABLE
#define FASTPATH_WORKER_PREFETCH0(p)    rte_prefetch0(p)
#define FASTPATH_WORKER_PREFETCH1(p)    rte_prefetch1(p)
#else
#define FASTPATH_WORKER_PREFETCH0(p)
#define FASTPATH_WORKER_PREFETCH1(p)
#endif

#define PREFETCH_OFFSET        3

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
	/* number of pkts received from NIC, and sent to KNI */
	uint64_t rx_packets;

	/* number of pkts received from NIC, but failed to send to KNI */
	uint64_t rx_dropped;

	/* number of pkts received from KNI, and sent to NIC */
	uint64_t tx_packets;

	/* number of pkts received from KNI, but failed to send to NIC */
	uint64_t tx_dropped;
};

/* kni device statistics array */
static struct kni_interface_stats kni_stats[FASTPATH_MAX_NIC_PORTS];

#define PKT_BURST_SZ    32

extern struct thread_master *mgr_master;

/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
void kni_ingress(struct rte_mbuf *m)
{
    unsigned lcore = rte_lcore_id();
    uint32_t n_mbufs, n_pkts, port_id;
    struct rte_kni *kni;
    struct mbuf_array *pkts_burst;
    rte_spinlock_t *kni_lock;

    port_id = m->port;

    if (port_id >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("kni_egress: invalid port %d\n", port_id);
        rte_pktmbuf_free(m);
        return;
    }

    kni = fastpath.kni[port_id];
    kni_lock = &fastpath.kni_lock[port_id];
    pkts_burst = &fastpath.kni_mbuf_out[lcore][port_id];

    /* Burst tx to kni */
    n_mbufs = pkts_burst->n_mbufs;
    pkts_burst->array[n_mbufs] = m;
    n_mbufs += 1;
    kni_stats[port_id].rx_packets += 1;

    if (n_mbufs < PKT_BURST_SZ) {
        pkts_burst->n_mbufs = n_mbufs;
    } else {
        rte_spinlock_lock(kni_lock);
        n_pkts = rte_kni_tx_burst(kni, pkts_burst->array, (uint16_t) n_mbufs);
        if (unlikely(n_pkts < n_mbufs)) {
            uint32_t k;
            fastpath_log_error("kni_ingress: send pkt failed, success %d expected %d",
                n_pkts, n_mbufs);
            for (k = n_pkts; k < n_mbufs; k ++) {
                struct rte_mbuf *pkt_to_free = pkts_burst->array[k];
                rte_pktmbuf_free(pkt_to_free);
            }

            kni_stats[port_id].rx_dropped += n_mbufs - n_pkts;
        }
        rte_spinlock_unlock(kni_lock);
        
        pkts_burst->n_mbufs = 0;
        fastpath.kni_mbuf_out_flush[lcore][port_id] = 0;
    }

    return;
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
void kni_egress(uint32_t port_id)
{
    uint8_t i;
    unsigned nb_tx, num;
    struct rte_kni *kni;
    struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

    if (port_id >= FASTPATH_MAX_NIC_PORTS) {
        fastpath_log_error("kni_egress: invalid port %d\n", port_id);
        return;
    }

    kni = fastpath.kni[port_id];

    /* Burst rx from kni */
    num = rte_kni_rx_burst(kni, pkts_burst, PKT_BURST_SZ);
    if (unlikely(num > PKT_BURST_SZ)) {
        fastpath_log_error("Error receiving from KNI\n");
        return;
    }
    
    /* Burst tx to eth */
    nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, (uint16_t)num);
    kni_stats[port_id].tx_packets += nb_tx;
    if (unlikely(nb_tx < num)) {
        /* Free mbufs not tx to NIC */
        for (i = nb_tx; i < num; i++) {
            rte_pktmbuf_free(pkts_burst[i]);
        }

        kni_stats[port_id].tx_dropped += num - nb_tx;
    }

    rte_kni_handle_request(kni);
}

static __inline__ void
fastpath_process_packet_bulk(struct rte_mbuf ** pkts, int nb_rx)
{
    int j;

    /* Prefetch first packets */
    for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
        rte_prefetch0(rte_pktmbuf_mtod(pkts[j], void *));

    /* Prefetch and handle already prefetched packets */
    for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[j + PREFETCH_OFFSET], void *));
        ethernet_input(pkts[j]);
    }

    /* Handle remaining prefetched packets */
    for (; j < nb_rx; j++)
        ethernet_input(pkts[j]);
}

static inline void
fastpath_rx_buffer_to_send (
    struct fastpath_params_rx *lp,
    uint32_t worker,
    struct rte_mbuf *mbuf,
    uint32_t bsz)
{
    uint32_t pos;
    int ret;

    pos = lp->mbuf_out[worker].n_mbufs;
    lp->mbuf_out[worker].array[pos ++] = mbuf;
    if (likely(pos < bsz)) {
        lp->mbuf_out[worker].n_mbufs = pos;
        return;
    }

    ret = rte_ring_sp_enqueue_bulk(
        lp->rings[worker],
        (void **) lp->mbuf_out[worker].array,
        bsz);

    if (unlikely(ret == -ENOBUFS)) {
        uint32_t k;
        for (k = 0; k < bsz; k ++) {
            struct rte_mbuf *m = lp->mbuf_out[worker].array[k];
            rte_pktmbuf_free(m);
        }
    }

    lp->mbuf_out[worker].n_mbufs = 0;
    lp->mbuf_out_flush[worker] = 0;

#if FASTPATH_STATS
    lp->rings_iters[worker] ++;
    if (likely(ret == 0)) {
        lp->rings_count[worker] ++;
    }
    if (unlikely(lp->rings_iters[worker] == FASTPATH_STATS)) {
        unsigned lcore = rte_lcore_id();

        printf("\tI/O RX %u out (worker %u): enq success rate = %.2f\n",
            lcore,
            (unsigned)worker,
            ((double) lp->rings_count[worker]) / ((double) lp->rings_iters[worker]));
        lp->rings_iters[worker] = 0;
        lp->rings_count[worker] = 0;
    }
#endif
}

static inline void
fastpath_rx(
    struct fastpath_params_rx *lp,
    uint32_t n_workers,
    uint32_t bsz_rd,
    uint32_t bsz_wr,
    uint8_t pos_lb)
{
    struct rte_mbuf *mbuf_1_0, *mbuf_1_1, *mbuf_2_0, *mbuf_2_1;
    uint8_t *data_1_0, *data_1_1 = NULL;
    uint32_t i;

    for (i = 0; i < lp->n_nic_queues; i ++) {
        uint8_t port = lp->nic_queues[i].port;
        uint8_t queue = lp->nic_queues[i].queue;
        uint32_t n_mbufs, j;

        if (queue == 0) {
            kni_egress(port);
        }

        n_mbufs = rte_eth_rx_burst(
            port,
            queue,
            lp->mbuf_in.array,
            (uint16_t) bsz_rd);

        if (unlikely(n_mbufs == 0)) {
            continue;
        }

#if FASTPATH_STATS
        lp->nic_queues_iters[i] ++;
        lp->nic_queues_count[i] += n_mbufs;
        if (unlikely(lp->nic_queues_iters[i] == FASTPATH_STATS)) {
            struct rte_eth_stats stats;
            unsigned lcore = rte_lcore_id();

            rte_eth_stats_get(port, &stats);

            printf("I/O RX %u in (NIC port %u): NIC drop ratio = %.2f avg burst size = %.2f\n",
                lcore,
                (unsigned) port,
                (double) stats.imissed / (double) (stats.imissed + stats.ipackets),
                ((double) lp->nic_queues_count[i]) / ((double) lp->nic_queues_iters[i]));
            lp->nic_queues_iters[i] = 0;
            lp->nic_queues_count[i] = 0;
        }
#endif

        mbuf_1_0 = lp->mbuf_in.array[0];
        mbuf_1_1 = lp->mbuf_in.array[1];
        data_1_0 = rte_pktmbuf_mtod(mbuf_1_0, uint8_t *);
        if (likely(n_mbufs > 1)) {
            data_1_1 = rte_pktmbuf_mtod(mbuf_1_1, uint8_t *);
        }

        mbuf_2_0 = lp->mbuf_in.array[2];
        mbuf_2_1 = lp->mbuf_in.array[3];
        FASTPATH_RX_PREFETCH0(mbuf_2_0);
        FASTPATH_RX_PREFETCH0(mbuf_2_1);

        for (j = 0; j + 3 < n_mbufs; j += 2) {
            struct rte_mbuf *mbuf_0_0, *mbuf_0_1;
            uint8_t *data_0_0, *data_0_1;
            uint32_t worker_0, worker_1;

            mbuf_0_0 = mbuf_1_0;
            mbuf_0_1 = mbuf_1_1;
            data_0_0 = data_1_0;
            data_0_1 = data_1_1;

            mbuf_1_0 = mbuf_2_0;
            mbuf_1_1 = mbuf_2_1;
            data_1_0 = rte_pktmbuf_mtod(mbuf_2_0, uint8_t *);
            data_1_1 = rte_pktmbuf_mtod(mbuf_2_1, uint8_t *);
            FASTPATH_RX_PREFETCH0(data_1_0);
            FASTPATH_RX_PREFETCH0(data_1_1);

            mbuf_2_0 = lp->mbuf_in.array[j+4];
            mbuf_2_1 = lp->mbuf_in.array[j+5];
            FASTPATH_RX_PREFETCH0(mbuf_2_0);
            FASTPATH_RX_PREFETCH0(mbuf_2_1);

            worker_0 = data_0_0[pos_lb] & (n_workers - 1);
            worker_1 = data_0_1[pos_lb] & (n_workers - 1);

            fastpath_rx_buffer_to_send(lp, worker_0, mbuf_0_0, bsz_wr);
            fastpath_rx_buffer_to_send(lp, worker_1, mbuf_0_1, bsz_wr);
        }

        /* Handle the last 1, 2 (when n_mbufs is even) or 3 (when n_mbufs is odd) packets  */
        for ( ; j < n_mbufs; j += 1) {
            struct rte_mbuf *mbuf;
            uint8_t *data;
            uint32_t worker;

            mbuf = mbuf_1_0;
            mbuf_1_0 = mbuf_1_1;
            mbuf_1_1 = mbuf_2_0;
            mbuf_2_0 = mbuf_2_1;

            data = rte_pktmbuf_mtod(mbuf, uint8_t *);

            FASTPATH_RX_PREFETCH0(mbuf_1_0);

            worker = data[pos_lb] & (n_workers - 1);

            fastpath_rx_buffer_to_send(lp, worker, mbuf, bsz_wr);
        }

        
    }
}

static inline void
fastpath_rx_flush(struct fastpath_params_rx *lp, uint32_t n_workers)
{
    uint32_t worker;

    for (worker = 0; worker < n_workers; worker ++) {
        int ret;

        if (likely((lp->mbuf_out_flush[worker] == 0) ||
                   (lp->mbuf_out[worker].n_mbufs == 0))) {
            lp->mbuf_out_flush[worker] = 1;
            continue;
        }

        ret = rte_ring_sp_enqueue_bulk(
            lp->rings[worker],
            (void **) lp->mbuf_out[worker].array,
            lp->mbuf_out[worker].n_mbufs);

        if (unlikely(ret < 0)) {
            uint32_t k;
            for (k = 0; k < lp->mbuf_out[worker].n_mbufs; k ++) {
                struct rte_mbuf *pkt_to_free = lp->mbuf_out[worker].array[k];
                rte_pktmbuf_free(pkt_to_free);
            }
        }

        lp->mbuf_out[worker].n_mbufs = 0;
        lp->mbuf_out_flush[worker] = 1;
    }
}

static void
fastpath_main_loop_rx(void)
{
    uint32_t lcore = rte_lcore_id();
    struct fastpath_params_rx *lp = &fastpath.lcore_params[lcore].rx;
    uint32_t n_workers = fastpath_get_lcores_worker();
    uint64_t i = 0;

    uint32_t bsz_rx_rd = fastpath.burst_size_rx_read;
    uint32_t bsz_rx_wr = fastpath.burst_size_rx_write;

    uint8_t pos_lb = fastpath.pos_lb;

    for ( ; ; ) {
        if (FASTPATH_RX_FLUSH && (unlikely(i == FASTPATH_RX_FLUSH))) {
            if (likely(lp->n_nic_queues > 0)) {
                fastpath_rx_flush(lp, n_workers);
            }

            i = 0;
        }

        if (likely(lp->n_nic_queues > 0)) {
            fastpath_rx(lp, n_workers, bsz_rx_rd, bsz_rx_wr, pos_lb);
        }

        i ++;
    }
}

static inline void
fastpath_worker(
    struct fastpath_params_worker *lp,
    uint32_t bsz_rd)
{
    uint32_t i;
    unsigned lcore = rte_lcore_id();

    for (i = 0; i < lp->n_rings; i ++) {
        struct rte_ring *ring_in = lp->rings[i];
        int ret;

        ret = rte_ring_sc_dequeue_bulk(
            ring_in,
            (void **) lp->mbuf_in.array,
            bsz_rd);

        if (unlikely(ret == -ENOENT)) {
            continue;
        }

        fastpath_process_packet_bulk(lp->mbuf_in.array, bsz_rd);

        rte_ip_frag_free_death_row(&fastpath.death_row[lcore], PREFETCH_OFFSET);
    }
}

static inline void
fastpath_worker_flush(struct fastpath_params_worker *lp)
{
    uint32_t port;
    unsigned lcore = rte_lcore_id();
    uint8_t *kni_mbuf_out_flush;
    struct mbuf_array *pkts_burst;
    struct rte_kni *kni;
    rte_spinlock_t *kni_lock;

    for (port = 0; port < FASTPATH_MAX_NIC_PORTS; port ++) {
        uint32_t n_pkts;

        if (likely((lp->mbuf_out_flush[port] == 0) ||
                   (lp->mbuf_out[port].n_mbufs == 0))) {
            lp->mbuf_out_flush[port] = 1;
            continue;
        }

        n_pkts = rte_eth_tx_burst(
            port, 
            lp->tx_queue_id[port], 
            lp->mbuf_out[port].array,
            lp->mbuf_out[port].n_mbufs);
        
        if (unlikely(n_pkts < lp->mbuf_out[port].n_mbufs)) {
            uint32_t k;
            for (k = 0; k < lp->mbuf_out[port].n_mbufs; k ++) {
                struct rte_mbuf *pkt_to_free = lp->mbuf_out[port].array[k];
                rte_pktmbuf_free(pkt_to_free);
            }
        }

        lp->mbuf_out[port].n_mbufs = 0;
        lp->mbuf_out_flush[port] = 1;
    }

    for (port = 0; port < FASTPATH_MAX_NIC_PORTS; port ++) {
        uint32_t n_pkts;

        kni = fastpath.kni[port];
        kni_lock = &fastpath.kni_lock[port];
        pkts_burst = &fastpath.kni_mbuf_out[lcore][port];
        kni_mbuf_out_flush = &fastpath.kni_mbuf_out_flush[lcore][port];

        if (likely((*kni_mbuf_out_flush == 0) ||
                   (pkts_burst->n_mbufs == 0))) {
            *kni_mbuf_out_flush = 1;
            continue;
        }

        rte_spinlock_lock(kni_lock);
        n_pkts = rte_kni_tx_burst(kni, pkts_burst->array, (uint16_t) pkts_burst->n_mbufs);
        if (unlikely(n_pkts < pkts_burst->n_mbufs)) {
            uint32_t k;
            fastpath_log_error("kni_ingress: send pkt failed, success %d expected %d",
                n_pkts, pkts_burst->n_mbufs);
            for (k = n_pkts; k < pkts_burst->n_mbufs; k ++) {
                struct rte_mbuf *pkt_to_free = pkts_burst->array[k];
                rte_pktmbuf_free(pkt_to_free);
            }

            kni_stats[port].rx_dropped += pkts_burst->n_mbufs - n_pkts;
        }
        rte_spinlock_unlock(kni_lock);
        
        pkts_burst->n_mbufs = 0;
        *kni_mbuf_out_flush = 1;
    }
}

static void
fastpath_main_loop_worker(void) {
    uint32_t lcore = rte_lcore_id();
    struct fastpath_params_worker *lp = &fastpath.lcore_params[lcore].worker;
    uint64_t i = 0;

    uint32_t bsz_rd = fastpath.burst_size_worker_read;

    for ( ; ; ) {
        if (FASTPATH_WORKER_FLUSH && (unlikely(i == FASTPATH_WORKER_FLUSH))) {
            fastpath_worker_flush(lp);
            i = 0;
        }

        fastpath_worker(lp, bsz_rd);

        i ++;
    }
}

static inline void
fastpath_rx_worker(
    struct fastpath_params_rx *lp,
    uint32_t bsz_rd)
{
    uint32_t i;
    unsigned lcore = rte_lcore_id();

    for (i = 0; i < lp->n_nic_queues; i ++) {
        uint8_t port = lp->nic_queues[i].port;
        uint8_t queue = lp->nic_queues[i].queue;
        uint32_t n_mbufs;

        if (queue == 0) {
            kni_egress(port);
        }

        n_mbufs = rte_eth_rx_burst(
            port,
            queue,
            lp->mbuf_in.array,
            (uint16_t) bsz_rd);

        if (unlikely(n_mbufs == 0)) {
            continue;
        }

#if FASTPATH_STATS
        lp->nic_queues_iters[i] ++;
        lp->nic_queues_count[i] += n_mbufs;
        if (unlikely(lp->nic_queues_iters[i] == FASTPATH_STATS)) {
            struct rte_eth_stats stats;

            rte_eth_stats_get(port, &stats);

            printf("RX Worker %u in (NIC port %u): NIC drop ratio = %.2f avg burst size = %.2f\n",
                lcore,
                (unsigned) port,
                (double) stats.imissed / (double) (stats.imissed + stats.ipackets),
                ((double) lp->nic_queues_count[i]) / ((double) lp->nic_queues_iters[i]));
            lp->nic_queues_iters[i] = 0;
            lp->nic_queues_count[i] = 0;
        }
#endif

        fastpath_process_packet_bulk(lp->mbuf_in.array, n_mbufs);

        rte_ip_frag_free_death_row(&fastpath.death_row[lcore], PREFETCH_OFFSET);
    }
}

static void
fastpath_main_loop_rx_worker(void)
{
    uint32_t lcore = rte_lcore_id();
    struct fastpath_params_rx *lp_rx = &fastpath.lcore_params[lcore].rx;
    struct fastpath_params_worker *lp_worker = &fastpath.lcore_params[lcore].worker;
    uint64_t i = 0;

    uint32_t bsz_rx_rd = fastpath.burst_size_rx_read;

    for ( ; ; ) {
        if (FASTPATH_WORKER_FLUSH && (unlikely(i == FASTPATH_WORKER_FLUSH))) {
            fastpath_worker_flush(lp_worker);
            i = 0;
        }

        if (likely(lp_rx->n_nic_queues > 0)) {
            fastpath_rx_worker(lp_rx, bsz_rx_rd);
        }

        i ++;
    }
}

static void
fastpath_main_loop_mgr(void)
{
    struct thread thread;
    
    while (thread_fetch(mgr_master, &thread)) {
        thread_call(&thread);
    }
}

int
fastpath_main_loop(__attribute__((unused)) void *arg)
{
    struct fastpath_lcore_params *lp;
    unsigned lcore;

    lcore = rte_lcore_id();
    lp = &fastpath.lcore_params[lcore];

    if (lcore == rte_get_master_lcore()) {
        printf("Master core %u mgr loop.\n", lcore);
        fastpath_main_loop_mgr();
    }

    if (lp->type == e_FASTPATH_LCORE_RX) {
        printf("Logical core %u (RX) main loop.\n", lcore);
        fastpath_main_loop_rx();
    }

    if (lp->type == e_FASTPATH_LCORE_WORKER) {
        printf("Logical core %u (Worker %u) main loop.\n",
            lcore,
            (unsigned) lp->worker.worker_id);
        fastpath_main_loop_worker();
    }

    if (lp->type == e_FASTPATH_LCORE_RX_WORKER) {
        printf("Logical core %u (RX Worker %u) main loop.\n",
            lcore,
            (unsigned) lp->worker.worker_id);
        fastpath_main_loop_rx_worker();
    }

    return 0;
}

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

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode    = ETH_MQ_RX_RSS,
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 1, /**< IP checksum offload enabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

static void
fastpath_assign_worker_ids(void)
{
    uint32_t lcore, worker_id;

    /* Assign ID for each worker */
    worker_id = 0;
    for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
        struct fastpath_params_worker *lp_worker = &fastpath.lcore_params[lcore].worker;

        if (fastpath.lcore_params[lcore].type != e_FASTPATH_LCORE_WORKER &&
            fastpath.lcore_params[lcore].type != e_FASTPATH_LCORE_RX_WORKER) {
            continue;
        }

        lp_worker->worker_id = worker_id;
        worker_id ++;
    }
}

static void
fastpath_init_frag_tables(void)
{
    uint64_t frag_cycles;

    frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * DEF_FLOW_TTL;

    fastpath.frag_tbl = rte_ip_frag_table_create(DEF_FLOW_NUM,
            IP_FRAG_TBL_BUCKET_ENTRIES, DEF_FLOW_NUM, frag_cycles, 0);
    if (fastpath.frag_tbl == NULL) {
        rte_panic("fastpath_init_frag_tables (%u) on socket 0\n", DEF_FLOW_NUM);
    }
}

static void
fastpath_init_mbuf_pools(void)
{
    unsigned socket, lcore;

    /* Init the buffer pools */
    for (socket = 0; socket < FASTPATH_MAX_SOCKETS; socket ++) {
        char name[32];
        if (fastpath_is_socket_used(socket) == 0) {
            continue;
        }

        snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
        printf("Creating the mbuf pool for socket %u ...\n", socket);
        fastpath.pktbuf_pools[socket] = rte_mempool_create(
            name,
            FASTPATH_DEFAULT_MEMPOOL_BUFFERS,
            FASTPATH_DEFAULT_MBUF_SIZE,
            FASTPATH_DEFAULT_MEMPOOL_CACHE_SIZE,
            sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL,
            rte_pktmbuf_init, NULL,
            socket,
            0);
        if (fastpath.pktbuf_pools[socket] == NULL) {
            rte_panic("Cannot create mbuf pool on socket %u\n", socket);
        }
    }

    for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
        if (fastpath.lcore_params[lcore].type == e_FASTPATH_LCORE_DISABLED) {
            continue;
        }

        socket = rte_lcore_to_socket_id(lcore);
        fastpath.lcore_params[lcore].pktbuf_pool = fastpath.pktbuf_pools[socket];
    }
}

static void
fastpath_init_indirect_mbuf_pools(void)
{
    unsigned socket, lcore;

    /* Init the buffer pools */
    for (socket = 0; socket < FASTPATH_MAX_SOCKETS; socket ++) {
        char name[32];
        if (fastpath_is_socket_used(socket) == 0) {
            continue;
        }

        snprintf(name, sizeof(name), "indirect_mbuf_pool_%u", socket);
        printf("Creating the indirect mbuf pool for socket %u ...\n", socket);
        fastpath.indirect_pools[socket] = rte_mempool_create(
            name,
            FASTPATH_DEFAULT_MEMPOOL_BUFFERS,
            FASTPATH_DEFAULT_INDIRECT_MBUF_SIZE,
            32,
            0,
            NULL, NULL,
            rte_pktmbuf_init, NULL,
            socket,
            0);
        if (fastpath.indirect_pools[socket] == NULL) {
            rte_panic("Cannot create mbuf pool on socket %u\n", socket);
        }
    }

    for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
        if (fastpath.lcore_params[lcore].type == e_FASTPATH_LCORE_DISABLED) {
            continue;
        }

        socket = rte_lcore_to_socket_id(lcore);
        fastpath.lcore_params[lcore].indirect_pool = fastpath.indirect_pools[socket];
    }
}

static void
fastpath_init_rings(void)
{
    unsigned lcore;

    /* Initialize the rings for the RX side */
    for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
        struct fastpath_params_rx *lp_rx = &fastpath.lcore_params[lcore].rx;
        unsigned socket_rx, lcore_worker;

        if ((fastpath.lcore_params[lcore].type != e_FASTPATH_LCORE_RX) ||
            (lp_rx->n_nic_queues == 0)) {
            continue;
        }

        socket_rx = rte_lcore_to_socket_id(lcore);

        for (lcore_worker = 0; lcore_worker < FASTPATH_MAX_LCORES; lcore_worker ++) {
            char name[32];
            struct fastpath_params_worker *lp_worker = &fastpath.lcore_params[lcore_worker].worker;
            struct rte_ring *ring = NULL;

            if (fastpath.lcore_params[lcore_worker].type != e_FASTPATH_LCORE_WORKER) {
                continue;
            }

            printf("Creating ring to connect I/O lcore %u (socket %u) with worker lcore %u ...\n",
                lcore,
                socket_rx,
                lcore_worker);
            snprintf(name, sizeof(name), "fastpath_ring_rx_s%u_io%u_w%u",
                socket_rx,
                lcore,
                lcore_worker);
            ring = rte_ring_create(
                name,
                fastpath.ring_size,
                socket_rx,
                RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (ring == NULL) {
                rte_panic("Cannot create ring to connect I/O core %u with worker core %u\n",
                    lcore,
                    lcore_worker);
            }

            lp_rx->rings[lp_rx->n_rings] = ring;
            lp_rx->n_rings ++;

            lp_worker->rings[lp_worker->n_rings] = ring;
            lp_worker->n_rings ++;
        }
    }

    for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
        struct fastpath_params_rx *lp_rx = &fastpath.lcore_params[lcore].rx;

        if ((fastpath.lcore_params[lcore].type != e_FASTPATH_LCORE_RX) ||
            (lp_rx->n_nic_queues == 0)) {
            continue;
        }

        if (lp_rx->n_rings != fastpath_get_lcores_worker()) {
            rte_panic("Algorithmic error (I/O RX rings)\n");
        }
    }

    for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
        struct fastpath_params_worker *lp_worker = &fastpath.lcore_params[lcore].worker;

        if (fastpath.lcore_params[lcore].type != e_FASTPATH_LCORE_WORKER) {
            continue;
        }

        if (lp_worker->n_rings != fastpath_get_lcores_rx()) {
            rte_panic("Algorithmic error (worker input rings)\n");
        }
    }
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;
    uint32_t n_rx_queues, n_tx_queues;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if ((port_mask & (1 << portid)) == 0)
                continue;
            n_rx_queues = fastpath_get_nic_rx_queues_per_port(portid);
            n_tx_queues = fastpath_get_nic_tx_queues_per_port(portid);
            if (n_rx_queues == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                        "Mbps - %s\n", (uint8_t)portid,
                        (unsigned)link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                            (uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == 0) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

static void
fastpath_init_nics(void)
{
    unsigned socket;
    uint32_t lcore;
    uint8_t port, queue;
    int ret;
    uint32_t n_rx_queues, n_tx_queues;

    /* Init NIC ports and queues, then start the ports */
    for (port = 0; port < FASTPATH_MAX_NIC_PORTS; port ++) {
        struct rte_mempool *pool;

        n_rx_queues = fastpath_get_nic_rx_queues_per_port(port);
        n_tx_queues = fastpath_get_lcores_rx_worker();

        if (n_rx_queues == 0) {
            continue;
        }

        /* Init port */
        printf("Initializing NIC port %u Rx queue %u Tx queue %u...\n", 
            (unsigned) port, n_rx_queues, n_tx_queues);
        ret = rte_eth_dev_configure(
            port,
            (uint8_t) n_rx_queues,
            (uint8_t) n_tx_queues,
            &port_conf);
        if (ret < 0) {
            rte_panic("Cannot init NIC port %u (%d)\n", (unsigned) port, ret);
        }
        rte_eth_promiscuous_enable(port);

        /* Init RX queues */
        for (queue = 0; queue < FASTPATH_MAX_RX_QUEUES_PER_NIC_PORT; queue ++) {
            if (fastpath.nic_rx_queue_mask[port][queue] == 0) {
                continue;
            }

            fastpath_get_lcore_for_nic_rx(port, queue, &lcore);
            socket = rte_lcore_to_socket_id(lcore);
            pool = fastpath.lcore_params[lcore].pktbuf_pool;

            printf("Initializing NIC port %u RX queue %u ...\n",
                (unsigned) port,
                (unsigned) queue);
            ret = rte_eth_rx_queue_setup(
                port,
                queue,
                (uint16_t) fastpath.nic_rx_ring_size,
                socket,
                NULL,
                pool);
            if (ret < 0) {
                rte_panic("Cannot init RX queue %u for port %u (%d)\n",
                    (unsigned) queue,
                    (unsigned) port,
                    ret);
            }
        }

        /* Init TX queues */
        for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore++) {
            struct fastpath_params_worker *lp_worker;

            if (fastpath.lcore_params[lcore].type != e_FASTPATH_LCORE_WORKER &&
                fastpath.lcore_params[lcore].type != e_FASTPATH_LCORE_RX_WORKER) {
                continue;
            }

            lp_worker = &fastpath.lcore_params[lcore].worker;
            queue = lp_worker->tx_queue_id[port] = lp_worker->worker_id;
            socket = rte_lcore_to_socket_id(lcore);
            printf("Initializing NIC port %u TX queue %u ...\n",
                (unsigned) port, (unsigned) queue);
            ret = rte_eth_tx_queue_setup(
                port,
                queue,
                (uint16_t) fastpath.nic_tx_ring_size,
                socket,
                NULL);
            if (ret < 0) {
                rte_panic("Cannot init TX queue 0 for port %d (%d)\n",
                    port,
                    ret);
            }
        }

        /* Start port */
        ret = rte_eth_dev_start(port);
        if (ret < 0) {
            rte_panic("Cannot start port %d (%d)\n", port, ret);
        }
    }

    check_all_ports_link_status(FASTPATH_MAX_NIC_PORTS, (~0x0));
}

void
fastpath_init(void)
{
    fastpath_assign_worker_ids();
    fastpath_init_frag_tables();
    fastpath_init_mbuf_pools();
    fastpath_init_indirect_mbuf_pools();
    fastpath_init_rings();
    fastpath_init_nics();

    setup();

    fastpath_log_set_screen_level(LOG_LEVEL);

    printf("Initialization completed.\n");
}

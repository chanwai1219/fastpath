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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
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
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_string_fns.h>

#include "main.h"

struct fastpath_params app;

static const char usage[] =
"                                                                               \n"
"    fastpath <EAL PARAMS> -- <APP PARAMS>                                      \n"
"                                                                               \n"
"Application manadatory parameters:                                             \n"
"    --rx \"(PORT, QUEUE, LCORE), ...\" : List of NIC RX ports and queues       \n"
"           handled by the I/O RX lcores                                        \n"
"    --w \"LCORE, ...\" : List of the worker lcores                             \n"
"                                                                               \n"
"Application optional parameters:                                               \n"
"    --rsz \"A, B, C\" : Ring sizes                                             \n"
"           A = Size (in number of buffer descriptors) of each of the NIC RX    \n"
"               rings read by the I/O RX lcores (default value is %u)           \n"
"           B = Size (in number of elements) of each of the SW rings used by the\n"
"               I/O RX lcores to send packets to worker lcores (default value is\n"
"               %u)                                                             \n"
"           C = Size (in number of buffer descriptors) of each of the NIC TX    \n"
"               rings written by I/O TX lcores (default value is %u)            \n"
"    --bsz \"(A, B), (C, D)\" :  Burst sizes                                    \n"
"           A = I/O RX lcore read burst size from NIC RX (default value is %u)  \n"
"           B = I/O RX lcore write burst size to output SW rings (default value \n"
"               is %u)                                                          \n"
"           C = Worker lcore read burst size from input SW rings (default value \n"
"               is %u)                                                          \n"
"           D = I/O TX lcore write burst size to NIC TX (default value is %u)   \n"
"    --pos-lb POS : Position of the 1-byte field within the input packet used by\n"
"           the I/O RX lcores to identify the worker lcore for the current      \n"
"           packet (default value is %u)                                        \n"
"    --no-numa: optional, disable numa awareness                                \n"
"    --l \"Log file\" : fastpath log file name                                  \n";

void
fastpath_print_usage(void)
{
	printf(usage,
		FASTPATH_DEFAULT_NIC_RX_RING_SIZE,
		FASTPATH_DEFAULT_RING_SIZE,
		FASTPATH_DEFAULT_NIC_TX_RING_SIZE,
		FASTPATH_DEFAULT_BURST_SIZE_RX_READ,
		FASTPATH_DEFAULT_BURST_SIZE_RX_WRITE,
		FASTPATH_DEFAULT_BURST_SIZE_WORKER_READ,
		FASTPATH_DEFAULT_BURST_SIZE_WORKER_WRITE,
		FASTPATH_DEFAULT_IO_RX_LB_POS
	);
}

#ifndef FASTPATH_ARG_RX_MAX_CHARS
#define FASTPATH_ARG_RX_MAX_CHARS     4096
#endif

#ifndef FASTPATH_ARG_RX_MAX_TUPLES
#define FASTPATH_ARG_RX_MAX_TUPLES    128
#endif

static int
str_to_unsigned_array(
	const char *s, size_t sbuflen,
	char separator,
	unsigned num_vals,
	unsigned *vals)
{
	char str[sbuflen+1];
	char *splits[num_vals];
	char *endptr = NULL;
	int i, num_splits = 0;

	/* copy s so we don't modify original string */
	snprintf(str, sizeof(str), "%s", s);
	num_splits = rte_strsplit(str, sizeof(str), splits, num_vals, separator);

	errno = 0;
	for (i = 0; i < num_splits; i++) {
		vals[i] = strtoul(splits[i], &endptr, 0);
		if (errno != 0 || *endptr != '\0')
			return -1;
	}

	return num_splits;
}

static int
str_to_unsigned_vals(
	const char *s,
	size_t sbuflen,
	char separator,
	unsigned num_vals, ...)
{
	unsigned i, vals[num_vals];
	va_list ap;

	num_vals = str_to_unsigned_array(s, sbuflen, separator, num_vals, vals);

	va_start(ap, num_vals);
	for (i = 0; i < num_vals; i++) {
		unsigned *u = va_arg(ap, unsigned *);
		*u = vals[i];
	}
	va_end(ap);
	return num_vals;
}

static int
parse_arg_rx(const char *arg)
{
	const char *p0 = arg, *p = arg;
	uint32_t n_tuples;

	if (strnlen(arg, FASTPATH_ARG_RX_MAX_CHARS + 1) == FASTPATH_ARG_RX_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while ((p = strchr(p0,'(')) != NULL) {
		struct fastpath_lcore_params *lp;
		uint32_t port, queue, lcore, i;

		p0 = strchr(p++, ')');
		if ((p0 == NULL) ||
		    (str_to_unsigned_vals(p, p0 - p, ',', 3, &port, &queue, &lcore) !=  3)) {
			return -2;
		}

		/* Enable port and queue for later initialization */
		if ((port >= FASTPATH_MAX_NIC_PORTS) || (queue >= FASTPATH_MAX_RX_QUEUES_PER_NIC_PORT)) {
			return -3;
		}
		if (app.nic_rx_queue_mask[port][queue] != 0) {
			return -4;
		}
		app.nic_rx_queue_mask[port][queue] = 1;

		/* Check and assign (port, queue) to I/O lcore */
		if (rte_lcore_is_enabled(lcore) == 0) {
			return -5;
		}

		if (lcore >= FASTPATH_MAX_LCORES) {
			return -6;
		}
		lp = &app.lcore_params[lcore];
		if (lp->type == e_FASTPATH_LCORE_WORKER) {
			lp->type = e_FASTPATH_LCORE_RX_WORKER;
		} else {
		    lp->type = e_FASTPATH_LCORE_RX;
		}
		for (i = 0; i < lp->rx.n_nic_queues; i ++) {
			if ((lp->rx.nic_queues[i].port == port) &&
			    (lp->rx.nic_queues[i].queue == queue)) {
				return -8;
			}
		}
		if (lp->rx.n_nic_queues >= FASTPATH_MAX_NIC_RX_QUEUES_PER_LCORE) {
			return -9;
		}
		lp->rx.nic_queues[lp->rx.n_nic_queues].port = (uint8_t) port;
		lp->rx.nic_queues[lp->rx.n_nic_queues].queue = (uint8_t) queue;
		lp->rx.n_nic_queues ++;

		n_tuples ++;
		if (n_tuples > FASTPATH_ARG_RX_MAX_TUPLES) {
			return -10;
		}
	}

	if (n_tuples == 0) {
		return -11;
	}

	return 0;
}

#ifndef FASTPATH_ARG_W_MAX_CHARS
#define FASTPATH_ARG_W_MAX_CHARS     4096
#endif

#ifndef FASTPATH_ARG_W_MAX_TUPLES
#define FASTPATH_ARG_W_MAX_TUPLES    FASTPATH_MAX_WORKER_LCORES
#endif

static int
parse_arg_w(const char *arg)
{
	const char *p = arg;
	uint32_t n_tuples;

	if (strnlen(arg, FASTPATH_ARG_W_MAX_CHARS + 1) == FASTPATH_ARG_W_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while (*p != 0) {
		struct fastpath_lcore_params *lp;
		uint32_t lcore;

		errno = 0;
		lcore = strtoul(p, NULL, 0);
		if ((errno != 0)) {
			return -2;
		}

		/* Check and enable worker lcore */
		if (rte_lcore_is_enabled(lcore) == 0) {
			return -3;
		}

		if (lcore >= FASTPATH_MAX_LCORES) {
			return -4;
		}
		lp = &app.lcore_params[lcore];
		if (lp->type == e_FASTPATH_LCORE_RX) {
			lp->type = e_FASTPATH_LCORE_RX_WORKER;
		} else {
		    lp->type = e_FASTPATH_LCORE_WORKER;
		}

		n_tuples ++;
		if (n_tuples > FASTPATH_ARG_W_MAX_TUPLES) {
			return -6;
		}

		p = strchr(p, ',');
		if (p == NULL) {
			break;
		}
		p ++;
	}

	if (n_tuples == 0) {
		return -7;
	}

	if ((n_tuples & (n_tuples - 1)) != 0) {
		return -8;
	}

	return 0;
}

#ifndef FASTPATH_ARG_RSZ_CHARS
#define FASTPATH_ARG_RSZ_CHARS 63
#endif

static int
parse_arg_rsz(const char *arg)
{
	if (strnlen(arg, FASTPATH_ARG_RSZ_CHARS + 1) == FASTPATH_ARG_RSZ_CHARS + 1) {
		return -1;
	}

	if (str_to_unsigned_vals(arg, FASTPATH_ARG_RSZ_CHARS, ',', 3,
			&app.nic_rx_ring_size,
			&app.ring_size,
			&app.nic_tx_ring_size) !=  3)
		return -2;


	if ((app.nic_rx_ring_size == 0) ||
		(app.nic_tx_ring_size == 0) ||
		(app.ring_size == 0)) {
		return -3;
	}

	return 0;
}

#ifndef FASTPATH_ARG_BSZ_CHARS
#define FASTPATH_ARG_BSZ_CHARS 63
#endif

static int
parse_arg_bsz(const char *arg)
{
	const char *p = arg, *p0;
	if (strnlen(arg, FASTPATH_ARG_BSZ_CHARS + 1) == FASTPATH_ARG_BSZ_CHARS + 1) {
		return -1;
	}

	p0 = strchr(p++, ')');
	if ((p0 == NULL) ||
	    (str_to_unsigned_vals(p, p0 - p, ',', 2, &app.burst_size_rx_read, &app.burst_size_rx_write) !=  2)) {
		return -2;
	}

	p = strchr(p0, '(');
	if (p == NULL) {
		return -3;
	}

	p0 = strchr(p++, ')');
	if ((p0 == NULL) ||
	    (str_to_unsigned_vals(p, p0 - p, ',', 2, &app.burst_size_worker_read, &app.burst_size_worker_write) !=  2)) {
		return -4;
	}

	if ((app.burst_size_rx_read == 0) ||
		(app.burst_size_rx_write == 0) ||
		(app.burst_size_worker_read == 0) ||
		(app.burst_size_worker_write == 0)) {
		return -7;
	}

	if ((app.burst_size_rx_read > FASTPATH_MBUF_ARRAY_SIZE) ||
		(app.burst_size_rx_write > FASTPATH_MBUF_ARRAY_SIZE) ||
		(app.burst_size_worker_read > FASTPATH_MBUF_ARRAY_SIZE) ||
		(app.burst_size_worker_write > FASTPATH_MBUF_ARRAY_SIZE)) {
		return -8;
	}

	return 0;
}

#ifndef FASTPATH_ARG_NUMERICAL_SIZE_CHARS
#define FASTPATH_ARG_NUMERICAL_SIZE_CHARS 15
#endif

static int
parse_arg_pos_lb(const char *arg)
{
	uint32_t x;
	char *endpt;

	if (strnlen(arg, FASTPATH_ARG_NUMERICAL_SIZE_CHARS + 1) == FASTPATH_ARG_NUMERICAL_SIZE_CHARS + 1) {
		return -1;
	}

	errno = 0;
	x = strtoul(arg, &endpt, 10);
	if (errno != 0 || endpt == arg || *endpt != '\0'){
		return -2;
	}

	if (x >= 64) {
		return -3;
	}

	app.pos_lb = (uint8_t) x;

	return 0;
}

/* Parse the argument given in the command line of the application */
int
fastpath_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{"rx", 1, 0, 0},
		{"w", 1, 0, 0},
		{"rsz", 1, 0, 0},
		{"bsz", 1, 0, 0},
		{"pos-lb", 1, 0, 0},
        {"no-numa", 0, 0, 0},
        {"l", 1, 0, 0},
		{NULL, 0, 0, 0}
	};
	uint32_t arg_w = 0;
	uint32_t arg_rx = 0;
	uint32_t arg_lpm = 0;
	uint32_t arg_rsz = 0;
	uint32_t arg_bsz = 0;
	uint32_t arg_pos_lb = 0;
	uint32_t arg_no_numa = 0;

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "N",
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case 0:
			if (!strcmp(lgopts[option_index].name, "rx")) {
				arg_rx = 1;
				ret = parse_arg_rx(optarg);
				if (ret) {
					printf("Incorrect value for --rx argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "w")) {
				arg_w = 1;
				ret = parse_arg_w(optarg);
				if (ret) {
					printf("Incorrect value for --w argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "rsz")) {
				arg_rsz = 1;
				ret = parse_arg_rsz(optarg);
				if (ret) {
					printf("Incorrect value for --rsz argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "bsz")) {
				arg_bsz = 1;
				ret = parse_arg_bsz(optarg);
				if (ret) {
					printf("Incorrect value for --bsz argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "pos-lb")) {
				arg_pos_lb = 1;
				ret = parse_arg_pos_lb(optarg);
				if (ret) {
					printf("Incorrect value for --pos-lb argument (%d)\n", ret);
					return -1;
				}
			}
            if (!strcmp(lgopts[option_index].name, "no-numa")) {
                arg_no_numa = 1;
				app.numa_on = 0;
			}
            if (!strcmp(lgopts[option_index].name, "l")) {
				fastpath_log_set_file(optarg);
			}
			break;

		default:
			return -1;
		}
	}

	/* Check that all mandatory arguments are provided */
	if ((arg_rx == 0) || (arg_w == 0) || (arg_lpm == 0)){
		printf("Not all mandatory arguments are present\n");
		return -1;
	}

	/* Assign default values for the optional arguments not provided */
	if (arg_rsz == 0) {
		app.nic_rx_ring_size = FASTPATH_DEFAULT_NIC_RX_RING_SIZE;
		app.nic_tx_ring_size = FASTPATH_DEFAULT_NIC_TX_RING_SIZE;
		app.ring_size = FASTPATH_DEFAULT_RING_SIZE;
	}

	if (arg_bsz == 0) {
		app.burst_size_rx_read = FASTPATH_DEFAULT_BURST_SIZE_RX_READ;
		app.burst_size_rx_write = FASTPATH_DEFAULT_BURST_SIZE_RX_WRITE;
		app.burst_size_worker_read = FASTPATH_DEFAULT_BURST_SIZE_WORKER_READ;
		app.burst_size_worker_write = FASTPATH_DEFAULT_BURST_SIZE_WORKER_WRITE;
	}

	if (arg_pos_lb == 0) {
		app.pos_lb = FASTPATH_DEFAULT_IO_RX_LB_POS;
	}
    
    if (arg_no_numa == 0) {
        app.numa_on = FASTPATH_DEFAULT_NUMA_ON;
    }
    
	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

int
fastpath_get_nic_rx_queues_per_port(uint8_t port)
{
	uint32_t i, count;

	if (port >= FASTPATH_MAX_NIC_PORTS) {
		return -1;
	}

	count = 0;
	for (i = 0; i < FASTPATH_MAX_RX_QUEUES_PER_NIC_PORT; i ++) {
		if (app.nic_rx_queue_mask[port][i] == 1) {
			count ++;
		}
	}

	return count;
}

int
fastpath_get_nic_tx_queues_per_port(uint8_t port)
{
	uint32_t lcore;
    int queue = 0;

    if (port >= FASTPATH_MAX_NIC_PORTS) {
		return -1;
	}

	for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
		struct fastpath_params_worker *lp = &app.lcore_params[lcore].worker;

		if (app.lcore_params[lcore].type != e_FASTPATH_LCORE_WORKER &&
            app.lcore_params[lcore].type != e_FASTPATH_LCORE_RX_WORKER) {
			continue;
		}

        if (lp->tx_queue_id[port] > queue) {
            queue = lp->tx_queue_id[port];
        }
	}

	return -1;
}

int
fastpath_get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t *lcore_out)
{
	uint32_t lcore;

	for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
		struct fastpath_params_rx *lp = &app.lcore_params[lcore].rx;
		uint32_t i;

		if (app.lcore_params[lcore].type != e_FASTPATH_LCORE_RX) {
			continue;
		}

		for (i = 0; i < lp->n_nic_queues; i ++) {
			if ((lp->nic_queues[i].port == port) &&
			    (lp->nic_queues[i].queue == queue)) {
				*lcore_out = lcore;
				return 0;
			}
		}
	}

	return -1;
}

int
fastpath_is_socket_used(uint32_t socket)
{
	uint32_t lcore;

	for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type == e_FASTPATH_LCORE_DISABLED) {
			continue;
		}

		if (socket == rte_lcore_to_socket_id(lcore)) {
			return 1;
		}
	}

	return 0;
}

uint32_t
fastpath_get_lcores_rx(void)
{
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
		struct fastpath_params_rx *lp_rx = &app.lcore_params[lcore].rx;

		if ((app.lcore_params[lcore].type != e_FASTPATH_LCORE_RX) ||
		    (lp_rx->n_nic_queues == 0)) {
			continue;
		}

		count ++;
	}

	return count;
}

uint32_t
fastpath_get_lcores_worker(void)
{
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type != e_FASTPATH_LCORE_WORKER &&
            app.lcore_params[lcore].type != e_FASTPATH_LCORE_RX_WORKER) {
			continue;
		}

		count ++;
	}

	if (count > FASTPATH_MAX_WORKER_LCORES) {
		rte_panic("Algorithmic error (too many worker lcores)\n");
		return 0;
	}

	return count;
}

void
fastpath_print_params(void)
{
	unsigned port, queue, lcore, i;

	/* Print NIC RX configuration */
	printf("NIC RX ports: ");
	for (port = 0; port < FASTPATH_MAX_NIC_PORTS; port ++) {
		uint32_t n_rx_queues = fastpath_get_nic_rx_queues_per_port((uint8_t) port);

		if (n_rx_queues == 0) {
			continue;
		}

		printf("%u (", port);
		for (queue = 0; queue < FASTPATH_MAX_RX_QUEUES_PER_NIC_PORT; queue ++) {
			if (app.nic_rx_queue_mask[port][queue] == 1) {
				printf("%u ", queue);
			}
		}
		printf(")  ");
	}
	printf(";\n");

	/* Print I/O lcore RX params */
	for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
		struct fastpath_params_rx *lp_rx = &app.lcore_params[lcore].rx;
        struct fastpath_params_worker *lp_worker = &app.lcore_params[lcore].worker;

		if ((app.lcore_params[lcore].type != e_FASTPATH_LCORE_RX &&
             app.lcore_params[lcore].type != e_FASTPATH_LCORE_RX_WORKER) ||
		    (lp_rx->n_nic_queues == 0)) {
			continue;
		}

		printf("I/O lcore %u (socket %u): ", lcore, rte_lcore_to_socket_id(lcore));

		printf("RX ports  ");
		for (i = 0; i < lp_rx->n_nic_queues; i ++) {
			printf("(%u, %u)  ",
				(unsigned) lp_rx->nic_queues[i].port,
				(unsigned) lp_rx->nic_queues[i].queue);
		}
		printf("; ");

        printf("Tx ports  ");
        for (i = 0; i < FASTPATH_MAX_NIC_PORTS; i ++) {
            if (lp_worker->tx_queue_id[i] != 0) {
                printf("(%u, %u)  ", i, (unsigned) lp_worker->tx_queue_id[i]);
            }
        }
        printf("; ");
	}

	/* Print worker lcore RX params */
	for (lcore = 0; lcore < FASTPATH_MAX_LCORES; lcore ++) {
		struct fastpath_params_worker *lp = &app.lcore_params[lcore].worker;

		if (app.lcore_params[lcore].type != e_FASTPATH_LCORE_WORKER) {
			continue;
		}

		printf("Worker lcore %u (socket %u) ID %u: ",
			lcore,
			rte_lcore_to_socket_id(lcore),
			(unsigned)lp->worker_id);

		printf("Input rings  ");
		for (i = 0; i < lp->n_rings; i ++) {
			printf("%p  ", lp->rings[i]);
		}

		printf(";\n");
	}

	printf("\n");

	/* Rings */
	printf("Ring sizes: NIC RX = %u; Worker in = %u; NIC TX = %u;\n",
		(unsigned) app.nic_rx_ring_size,
		(unsigned) app.ring_size,
		(unsigned) app.nic_tx_ring_size);

	/* Bursts */
	printf("Burst sizes: I/O RX (rd = %u, wr = %u); Worker (rd = %u, wr = %u);\n",
		(unsigned) app.burst_size_rx_read,
		(unsigned) app.burst_size_rx_write,
		(unsigned) app.burst_size_worker_read,
		(unsigned) app.burst_size_worker_write);
}

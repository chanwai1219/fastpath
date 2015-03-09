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

#include "include/fastpath.h"

static void
signal_handler(int signum)
{
    int j, nptrs;
    void *buffer[100];
    char **strings;

    RTE_SET_USED(signum);

    fastpath_cleanup();

    nptrs = backtrace(buffer, 100);
    printf("backtrace() returned %d addresses\n", nptrs);

    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
       perror("backtrace_symbols");
       exit(EXIT_FAILURE);
    }

    for (j = 0; j < nptrs; j++) {
       printf("%s\n", strings[j]);
    }

    free(strings);
    exit(0);
}

int
main(int argc, char **argv)
{
    uint32_t lcore;
    int ret;

    /* Associate signal_hanlder function with USR signals */
    struct sigaction act;

    act.sa_handler = signal_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

    sigaction(SIGINT,  &act, 0);
    sigaction(SIGQUIT, &act, 0);
    sigaction(SIGTERM, &act, 0);
    sigaction(SIGSTOP, &act, 0);
    sigaction(SIGTSTP, &act, 0);
    sigaction(SIGABRT, &act, 0);
    sigaction(SIGFPE,  &act, 0);
    sigaction(SIGSEGV, &act, 0);

    fastpath_init_log();

    /* Init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        return -1;
    argc -= ret;
    argv += ret;

    /* Parse application arguments (after the EAL ones) */
    ret = fastpath_parse_args(argc, argv);
    if (ret < 0) {
        fastpath_print_usage();
        return -1;
    }

    /* Init */
    fastpath_init();
    fastpath_print_params();

    /* Launch per-lcore init on every slave lcore */
    rte_eal_mp_remote_launch(fastpath_main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if (rte_eal_wait_lcore(lcore) < 0) {
            return -1;
        }
    }

    /* Release resources */
    fastpath_cleanup();

    return 0;
}


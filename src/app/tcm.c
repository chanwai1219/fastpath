
#include "include/fastpath.h"

#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

#define TCM_FLOWS_MAX       256
#define TCM_PKT_COLOR_POS   offsetof(struct ipv4_hdr, type_of_service)

#ifndef RTE_METER_TB_PERIOD_MIN
#define RTE_METER_TB_PERIOD_MIN      100
#endif

enum {
    TCM_MODE_SRTCM_COLOR_BLIND,
    TCM_MODE_SRTCM_COLOR_AWARE,
    TCM_MODE_TRTCM_COLOR_BLIND,
    TCM_MODE_TRTCM_COLOR_AWARE,
    TCM_MODE_MAX
};

enum policer_action {
        GREEN = e_RTE_METER_GREEN,
        YELLOW = e_RTE_METER_YELLOW,
        RED = e_RTE_METER_RED,
        DROP = 3,
};

enum policer_action policer_table[e_RTE_METER_COLORS][e_RTE_METER_COLORS] =
{
	{ GREEN, RED, RED},
	{ DROP, YELLOW, RED},
	{ DROP, DROP, RED}
};

union ipv4_5tuple_host {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	__m128i xmm;
};

struct tcm_private {
    void *flows;
    struct module *interface;
    struct module *route;
};

static uint32_t tcm_mode;
static __m128i mask0;

struct rte_meter_srtcm_params app_srtcm_params[] = {
	{.cir = 1000000 * 46,  .cbs = 2048, .ebs = 2048},
};

struct rte_meter_trtcm_params app_trtcm_params[] = {
	{.cir = 1000000 * 46,  .pir = 1500000 * 46,  .cbs = 2048, .pbs = 2048},
};

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
	uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash_1word(k->ip_src, init_val);
	init_val = rte_jhash_1word(k->ip_dst, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
	return (init_val);
}

static void
tcm_configure_flow_table(struct tcm_private *private)
{
	uint32_t i, j;
    struct rte_meter_srtcm *srtcm_flow;
    struct rte_meter_trtcm *trtcm_flow;

    switch (tcm_mode) {
    case TCM_MODE_SRTCM_COLOR_BLIND:
    case TCM_MODE_SRTCM_COLOR_AWARE:
        srtcm_flow = (struct rte_meter_srtcm *)private->flows;
        for (i = 0, j = 0; i < TCM_FLOWS_MAX; i ++, j = (j + 1) % RTE_DIM(app_srtcm_params)){
		    rte_meter_srtcm_config(&srtcm_flow[i], &app_srtcm_params[j]);
	    }
        break;

    case TCM_MODE_TRTCM_COLOR_BLIND:
    case TCM_MODE_TRTCM_COLOR_AWARE:
        trtcm_flow = (struct rte_meter_trtcm *)private->flows;
        for (i = 0, j = 0; i < TCM_FLOWS_MAX; i ++, j = (j + 1) % RTE_DIM(app_trtcm_params)){
    		rte_meter_trtcm_config(&trtcm_flow[i], &app_trtcm_params[j]);
    	}
        break;
    
    default:
        fastpath_log_error("invalid tcm mode %d\n", tcm_mode);
        break;
    };
}

static inline void 
tcm_set_pkt_color(uint8_t *pkt_data, enum policer_action color)
{
	pkt_data[TCM_PKT_COLOR_POS] = (uint8_t)color;
}

static inline int
tcm_pkt_handle(struct tcm_private *private, struct rte_mbuf *pkt, uint64_t time)
{
	uint8_t input_color, output_color;
    uint8_t flow_id;
	uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt);
	input_color = pkt_data[TCM_PKT_COLOR_POS];
	enum policer_action action;
    __m128i data;
    union ipv4_5tuple_host key;
    struct rte_meter_srtcm *srtcm_flow;
    struct rte_meter_trtcm *trtcm_flow;

    /* Get 5 tuple: dst port, src port, dst IP address, src IP address and protocol */
    data = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(pkt, unsigned char *) + 
        offsetof(struct ipv4_hdr, time_to_live)));
    
    key.xmm = _mm_and_si128(data, mask0);

    flow_id = ipv4_hash_crc(&data, sizeof(union ipv4_5tuple_host), 0);
    flow_id = flow_id & (TCM_FLOWS_MAX - 1);

	/* color input is not used for blind modes */
    switch (tcm_mode) {
    case TCM_MODE_SRTCM_COLOR_BLIND:
        srtcm_flow = (struct rte_meter_srtcm *)private->flows;
        output_color = (uint8_t) rte_meter_srtcm_color_blind_check(
            &srtcm_flow[flow_id], time, pkt_len);
        break;
    case TCM_MODE_SRTCM_COLOR_AWARE:
        srtcm_flow = (struct rte_meter_srtcm *)private->flows;
        output_color = (uint8_t) rte_meter_srtcm_color_aware_check(
            &srtcm_flow[flow_id], time, pkt_len,
		    (enum rte_meter_color) input_color);
        break;
    case TCM_MODE_TRTCM_COLOR_BLIND:
        trtcm_flow = (struct rte_meter_trtcm *)private->flows;
        output_color = (uint8_t) rte_meter_trtcm_color_blind_check(
            &trtcm_flow[flow_id], time, pkt_len);
        break;
    case TCM_MODE_TRTCM_COLOR_AWARE:
        trtcm_flow = (struct rte_meter_trtcm *)private->flows;
        output_color = (uint8_t) rte_meter_trtcm_color_aware_check(
            &trtcm_flow[flow_id], time, pkt_len,
            (enum rte_meter_color) input_color);
        break;
    default:
        fastpath_log_debug("tcm_pkt_handle: invalid tcm_mode %d\n", tcm_mode);
        output_color = e_RTE_METER_RED;
        break;
    }

	/* Apply policing and set the output color */
	action = policer_table[input_color][output_color];
	tcm_set_pkt_color(pkt_data, action);

	return action;
}

void tcm_receive(struct rte_mbuf *m, struct module *peer, struct module *tcm)
{
    uint64_t current_time = rte_rdtsc();
    struct tcm_private *private = (struct tcm_private *)tcm->private;

    RTE_SET_USED(peer);

    if (tcm_pkt_handle(private, m, current_time) == DROP) {
        rte_pktmbuf_free(m);
    } else {
        SEND_PKT(m, tcm, private->route, PKT_DIR_RECV);
    }
}

void tcm_xmit(struct rte_mbuf *m, struct module *peer, struct module *tcm)
{
    struct tcm_private *private = (struct tcm_private *)tcm->private;

    RTE_SET_USED(peer);

    SEND_PKT(m, tcm, private->interface, PKT_DIR_XMIT);
}

int tcm_handle_msg(struct module *tcm, 
    struct msg_hdr *req, struct msg_hdr *resp)
{
    int ret;
    struct tcm_private *private = (struct tcm_private *)tcm->private;

    RTE_SET_USED(private);
    
    resp->cmd = req->cmd;

    switch (req->cmd) {
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

int tcm_connect(struct module *local, struct module *peer, void *param)
{
    struct tcm_private *private;

    RTE_SET_USED(param);

    if (local == NULL || peer == NULL) {
        fastpath_log_error("interface_connect: invalid local %p peer %p\n", 
            local, peer);
        return -EINVAL;
    }

    fastpath_log_info("tcm_connect: local %s peer %s\n", local->name, peer->name);

    private = (struct tcm_private *)local->private;

    if (peer->type == MODULE_TYPE_INTERFACE || peer->type == MODULE_TYPE_ACL) {
        private->interface = peer;
        
        peer->connect(peer, local, NULL);
    } else if (peer->type == MODULE_TYPE_ROUTE) {
        private->route = peer;
    } else {
        fastpath_log_error("tcm_connect: invalid peer type %d\n", peer->type);
        return -ENOENT;
    }

    return 0;
}

struct module * tcm_init(uint16_t index, uint16_t mode)
{
    struct module *tcm;
    struct tcm_private *private;

    if (index >= ROUTE_MAX_LINK) {
        fastpath_log_error("tcm_init: invalid index %d\n", index);
        return NULL;
    }

    if (mode >= TCM_MODE_MAX) {
        fastpath_log_error("tcm_init: invalid mode %d\n", mode);
        return NULL;
    }

    tcm_mode = mode;
    mask0 = _mm_set_epi32(ALL_32_BITS, ALL_32_BITS, ALL_32_BITS, BIT_8_TO_15);

    tcm = rte_zmalloc(NULL, sizeof(struct module), 0);
    if (tcm == NULL) {
        fastpath_log_error("tcm_init: malloc module failed\n");
        return NULL;
    }

    private = rte_zmalloc(NULL, sizeof(struct tcm_private), 0);
    if (private == NULL) {
        rte_free(tcm);
        
        fastpath_log_error("tcm_init: malloc tcm_private failed\n");
        return NULL;
    }

    switch (tcm_mode) {
    case TCM_MODE_SRTCM_COLOR_BLIND:
    case TCM_MODE_SRTCM_COLOR_AWARE:
        private->flows = rte_malloc(NULL, sizeof(struct rte_meter_srtcm) * TCM_FLOWS_MAX, 0);
        break;
    
    case TCM_MODE_TRTCM_COLOR_BLIND:
    case TCM_MODE_TRTCM_COLOR_AWARE:
        private->flows = rte_malloc(NULL, sizeof(struct rte_meter_trtcm) * TCM_FLOWS_MAX, 0);
        break;
        
    default:
        break;
    }

    if (private->flows == NULL) {
        rte_free(private);
        rte_free(tcm);
        
        fastpath_log_error("tcm_init: malloc tcm flows failed\n");
        return NULL;
    }

    tcm_configure_flow_table(private);

    snprintf(tcm->name, sizeof(tcm->name), "tcm%d", index);
    tcm->type = MODULE_TYPE_TCM;
    tcm->receive = tcm_receive;
    tcm->transmit = tcm_xmit;
    tcm->connect = tcm_connect;
    tcm->message = tcm_handle_msg;
    tcm->private = private;

    return tcm;
}



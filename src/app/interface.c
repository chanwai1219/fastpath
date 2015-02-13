
#include "fastpath.h"

#define INTERFACE_INDEX_MAX     VLAN_VID_MAX

#define INTERFACE_LINK_DOWN     0
#define INTERFACE_LINK_UP       1

struct interface_private {
    uint16_t ifindex;
    uint8_t state;
    uint8_t reserved;
    struct module *ipv4;
    struct module *ipv6;
    struct module *bridge;
};

struct module *interface_modules[INTERFACE_INDEX_MAX];

static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
    /* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
    /*
     * 1. The packet length reported by the Link Layer must be large
     * enough to hold the minimum length legal IP datagram (20 bytes).
     */
    if (link_len < sizeof(struct ipv4_hdr))
        return -1;

    /* 2. The IP checksum must be correct. */
    /* this is checked in H/W */

    /*
     * 3. The IP version number must be 4. If the version number is not 4
     * then the packet may be another version of IP, such as IPng or
     * ST-II.
     */
    if (((pkt->version_ihl) >> 4) != 4)
        return -3;
    /*
     * 4. The IP header length field must be large enough to hold the
     * minimum length legal IP datagram (20 bytes = 5 words).
     */
    if ((pkt->version_ihl & 0xf) < 5)
        return -4;

    /*
     * 5. The IP total length field must be large enough to hold the IP
     * datagram header, whose length is specified in the IP header length
     * field.
     */
    if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
        return -5;

    return 0;
}

void interface_receive(struct rte_mbuf *m, struct module *peer, struct module *iface)
{
    uint64_t cur_tsc = rte_rdtsc();
    struct ipv4_hdr *ipv4_hdr;
    struct ipv6_hdr *ipv6_hdr;
    struct interface_private *private;
    struct rte_ip_frag_tbl *tbl;
    struct rte_ip_frag_death_row *dr;

    RTE_SET_USED(peer);

    private = (struct interface_private *)iface->private;

    if (m->ol_flags & (PKT_RX_IPV4_HDR)) {
        ipv4_hdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);

        fastpath_log_debug("interface %s receive pkt "NIPQUAD_FMT" ==> "NIPQUAD_FMT"\n",
            iface->name, NIPQUAD(ipv4_hdr->src_addr), NIPQUAD(ipv4_hdr->dst_addr));

        /* Check to make sure the packet is valid (RFC1812) */
        if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt_len) < 0) {
            rte_pktmbuf_free(m);
            return;
        }

        if (rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr)) {
            struct rte_mbuf *mo;

            tbl = fastpath.frag_tbl;
            dr = &fastpath.death_row;

            /* prepare mbuf: setup l2_len/l3_len. */
            m->l2_len = 0;
            m->l3_len = sizeof(*ipv4_hdr);

            /* process this fragment. */
            mo = rte_ipv4_frag_reassemble_packet(tbl, dr, m, cur_tsc, ipv4_hdr);
            if (mo == NULL)
                /* no packet to send out. */
                return;

            /* we have our packet reassembled. */
            if (mo != m) {
                m = mo;
                ipv4_hdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);
            }
        }

        SEND_PKT(m, iface, private->ipv4, PKT_DIR_RECV);
    } else if (m->ol_flags & (PKT_RX_IPV6_HDR | PKT_RX_IPV6_HDR_EXT)) {
        struct ipv6_extension_fragment *frag_hdr;

        ipv6_hdr = rte_pktmbuf_mtod(m, struct ipv6_hdr *);
        frag_hdr = rte_ipv6_frag_get_ipv6_fragment_header(ipv6_hdr);

        if (frag_hdr != NULL) {
            struct rte_mbuf *mo;

            tbl = fastpath.frag_tbl;
            dr  = &fastpath.death_row;

            /* prepare mbuf: setup l2_len/l3_len. */
            m->l2_len = 0;
            m->l3_len = sizeof(*ipv6_hdr) + sizeof(*frag_hdr);

            mo = rte_ipv6_frag_reassemble_packet(tbl, dr, m, cur_tsc, ipv6_hdr, frag_hdr);
            if (mo == NULL)
                return;

            if (mo != m) {
                m = mo;
                ipv6_hdr = rte_pktmbuf_mtod(m, struct ipv6_hdr *);
            }
        }

        SEND_PKT(m, iface, private->ipv6, PKT_DIR_RECV);
    }
}

void interface_xmit(struct rte_mbuf *m, struct module *peer, struct module *iface)
{
    int32_t i, n_frags;
    int socketid = rte_socket_id();
    struct rte_mbuf *pkts_out[MAX_FRAG_NUM];
    struct interface_private *private = (struct interface_private *)iface->private;

    RTE_SET_USED(peer);

    if (private->state == INTERFACE_LINK_DOWN) {
        fastpath_log_debug("interface_xmit: interface %s link down\n", iface->name);
        rte_pktmbuf_free(m);
        return;
    }

    if (m->ol_flags & PKT_RX_IPV4_HDR) {
        /* if we don't need to do any fragmentation */
        if (likely (IPV4_MTU_DEFAULT >= m->pkt_len)) {
            SEND_PKT(m, iface, private->bridge, PKT_DIR_XMIT);
        } else {
            n_frags = rte_ipv4_fragment_packet(m,
                &pkts_out[0],
                MAX_FRAG_NUM,
                IPV4_MTU_DEFAULT,
                fastpath.pktbuf_pools[socketid], fastpath.indirect_pools[socketid]);

            /* Free input packet */
            rte_pktmbuf_free(m);

            /* If we fail to fragment the packet */
            if (unlikely (n_frags < 0))
                return;

            for (i = 0; i < n_frags; i++) {
                SEND_PKT(pkts_out[i], iface, private->bridge, PKT_DIR_XMIT);
            }
        }
    } else if (m->ol_flags & PKT_RX_IPV6_HDR) {
        /* if we don't need to do any fragmentation */
        if (likely (IPV6_MTU_DEFAULT >= m->pkt_len)) {
            SEND_PKT(m, iface, private->bridge, PKT_DIR_XMIT);
        } else {
            n_frags = rte_ipv6_fragment_packet(m,
                &pkts_out[0],
                MAX_FRAG_NUM,
                IPV6_MTU_DEFAULT,
                fastpath.pktbuf_pools[socketid], fastpath.indirect_pools[socketid]);

            /* Free input packet */
            rte_pktmbuf_free(m);

            /* If we fail to fragment the packet */
            if (unlikely (n_frags < 0))
                return;

            for (i = 0; i < n_frags; i++) {
                SEND_PKT(pkts_out[i], iface, private->bridge, PKT_DIR_XMIT);
            }
        }
    }
}

int interface_connect(struct module *local, struct module *peer, void *param)
{
    struct interface_private *private;

    RTE_SET_USED(param);

    if (local == NULL || peer == NULL) {
        fastpath_log_error("interface_connect: invalid local %p peer %p\n", 
            local, peer);
        return -EINVAL;
    }

    fastpath_log_info("interface_connect: local %s peer %s\n", local->name, peer->name);

    private = (struct interface_private *)local->private;

    if (peer->type == MODULE_TYPE_BRIDGE) {
        private->bridge = peer;
        
        peer->connect(peer, local, NULL);
    } else if (peer->type == MODULE_TYPE_IPFWD) {
        private->ipv4 = peer;
        private->ipv6 = peer;
    } else {
        fastpath_log_error("interface_connect: invalid peer type %d\n", peer->type);
        return -ENOENT;
    }

    return 0;
}


struct module * interface_init(uint16_t ifidx)
{
    struct module *iface;
    struct interface_private *private;

    if (ifidx >= INTERFACE_INDEX_MAX) {
        fastpath_log_error("interface_init: invalid if index %d\n", ifidx);
        return NULL;
    }

    iface = rte_zmalloc(NULL, sizeof(struct module), 0);
    if (iface == NULL) {
        fastpath_log_error("interface_init: malloc module failed\n");
        return NULL;
    }

    private = rte_zmalloc(NULL, sizeof(struct interface_private), 0);
    if (private == NULL) {
        rte_free(iface);
        
        fastpath_log_error("interface_init: malloc interface_private failed\n");
        return NULL;
    }

    iface->type = MODULE_TYPE_INTERFACE;
    snprintf(iface->name, sizeof(iface->name), "eif%d", ifidx);

    private->ifindex = ifidx;
    private->state = INTERFACE_LINK_UP;

    iface->private = (void *)private;

    interface_modules[ifidx] = iface;

    return iface;    
}




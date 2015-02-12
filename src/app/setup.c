
#include "fastpath.h"

void setup(void)
{
    unsigned port;
    struct module *eth[FASTPATH_MAX_NIC_PORTS] = {0}, *br;

    fastpath_log_info("%s %d\n", __func__, __LINE__);

    for (port = 0; port < FASTPATH_MAX_NIC_PORTS; port ++) {
        uint32_t n_rx_queues = fastpath_get_nic_rx_queues_per_port((uint8_t) port);

        if (n_rx_queues == 0) {
            continue;
        }

        eth[port] = ethernet_init(port, VLAN_MODE_TRUNK, 1);
    }

    br = bridge_init(1);
    for (port = 0; port < FASTPATH_MAX_NIC_PORTS; port ++) {
        if (eth[port] != NULL) {
            br->connect(br, eth[port], (void *)&port);
        }
    }
    
}


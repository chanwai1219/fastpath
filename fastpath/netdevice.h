
#ifndef __NETDEVICE_H__
#define __NETDEVICE_H__

enum {
    NET_DEVICE_TYPE_ETHERNET,
    NET_DEVICE_TYPE_VLAN,
    NET_DEVICE_TYPE_BRIDGE,
    NET_DEVICE_TYPE_INTERFACE,
}

struct net_device {
    char name[IFNAMSIZ];
    uint16_t ifindex;
    uint16_t type;
    void (*receive)(struct rte_mbuf *m, struct net_device *dev);
    void (*transmit)(struct rte_mbuf *m, struct net_device *dev);
    void *private;
}

#endif

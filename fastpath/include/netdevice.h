
#ifndef __NETDEVICE_H__
#define __NETDEVICE_H__

enum {
    NET_DEVICE_TYPE_ETHERNET,
    NET_DEVICE_TYPE_VLAN,
    NET_DEVICE_TYPE_BRIDGE,
    NET_DEVICE_TYPE_INTERFACE,
};

struct net_device {
#define NAME_SIZE   16
    char name[NAME_SIZE];
    uint16_t ifindex;
    uint16_t type;
    void (*receive)(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev);
    void (*transmit)(struct rte_mbuf *m, struct net_device *peer, struct net_device *dev);
    void *private;
};

#endif

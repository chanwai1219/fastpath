
struct net_device {
    char name[IFNAMSIZ];
    int ifindex;
    int (*receive)(struct rte_mbuf *m, struct net_device *dev);
    int (*transmit)(struct rte_mbuf *m, struct net_device *dev);
    void *private;
}


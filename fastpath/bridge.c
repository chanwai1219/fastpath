
#include "fastpath.h"

struct net_device *bridge_dev[FASTPATH_MAX_NIC_PORTS];

typedef struct bridge_private {
    uint16_t vid;
};



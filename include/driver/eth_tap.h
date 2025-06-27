#ifndef ETH_TAP_H
#define ETH_TAP_H

#include "net_irq.h"

#define ETHER_TAP_IRQ (IRQ_BASE + 2)

extern struct net_dev *
eth_tap_init(const char *name, const char *addr);

#endif

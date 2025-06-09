#ifndef DUMMY_H
#define DUMMY_H

#include "net_irq.h"

#define DUM_IRQ IRQ_BASE
#define DUM_MTU 32000

extern struct net_dev *
dummy_init();

#endif

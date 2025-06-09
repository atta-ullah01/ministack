#ifndef LOOPBACK_H
#define LOOPBACK_H

#include "utils.h"
#include "net_dev.h"

#define LOOPBACK_MTU		3200
#define LOOPBACK_QUEUE_LIMIT	1000
#define LOOPBACK_IRQ		(IRQ_BASE + 1)

struct loopback
{
	int irq;
	pthread_mutex_t mutex;
	struct queue queue;
};

struct loopback_queue_entry
{
	uint16_t type;
	size_t len;
	uint8_t data[];
};

extern struct net_dev *
loopback_init(void);

#endif

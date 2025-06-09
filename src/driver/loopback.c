#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "loopback.h"
#include "net_dev.h"
#include "net_irq.h"
#include "utils.h"

static int
loopback_transmit(struct net_dev *dev, const uint8_t *data, size_t len, uint16_t type, const uint8_t *dst)
{
	struct loopback *lo = (struct loopback *)dev->driv;
	pthread_mutex_lock(&lo->mutex);
	if (lo->queue.size >= LOOPBACK_QUEUE_LIMIT) {
		log_error("queue is full, dev=%s", dev->name);
		return -1;
	}
	struct loopback_queue_entry *entry = malloc(sizeof(*entry) + len);
	if (!entry) {
		log_error(strerror(errno));
		return -1;
	}

	entry->type = type;
	entry->len = len;
	memcpy(entry->data, data, len);
	queue_push(&lo->queue, entry);
	pthread_mutex_unlock(&lo->mutex);
	log_debug("queue pushed (num:%zu), dev=%s, type=0x%04x, len=%zd", lo->queue.size, dev->name, type, len);
	debug_dump(data, len);
	irq_raise(lo->irq);
	return 0;
}

static int
loopback_isr(unsigned int irq, void *dev)
{
	struct net_dev *ldev = (struct net_dev *)dev;
	struct loopback *lo = ldev->driv;
	pthread_mutex_lock(&lo->mutex);
	while (lo->queue.size) {
		struct loopback_queue_entry *entry = queue_pop(&lo->queue);
		log_debug("queue popped (num:%d), dev=%s, type=0x%04x, len=%zd", lo->queue.size, ldev->name, entry->type, entry->len);
		debug_dump(entry->data, entry->len);
		net_input_handler(ldev, entry->data, entry->len);
		free(entry);
	}
	pthread_mutex_unlock(&lo->mutex);
	return 0;
}

static struct net_dev_ops lo_ops = {
	.transmit = loopback_transmit
};

struct net_dev *
loopback_init(void)
{
	struct net_dev *dev; 
	dev = net_dev_alloc();
	if (!dev)
		return NULL;

	dev->type = NET_DEV_TYPE_LOOPBACK;
	dev->mtu = LOOPBACK_MTU;
	dev->flags = NET_DEV_FLAG_LOOPBACK;
	dev->hlen = 0;
	dev->alen = 0;
	dev->ops = &lo_ops;

	struct loopback *lo;
	lo = malloc(sizeof(*lo));
	if (!lo) {
		free(dev);
		log_error("loopback_init: %s", strerror(errno));
		return NULL;
	}
	lo->irq = LOOPBACK_IRQ;
	pthread_mutex_init(&lo->mutex, NULL);
	queue_init(&lo->queue);
	dev->driv = lo;
	if (net_dev_register(dev) < 0) {
		free(dev);
		free(lo);
		log_error("net_dev_register() failure");
		return NULL;
	}

	if (irq_register(LOOPBACK_IRQ, loopback_isr, 0, dev->name, dev) < 0) {
		free(dev);
		free(lo);
		return NULL;
	}
	
	return dev;
}

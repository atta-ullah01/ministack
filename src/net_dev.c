#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "net_dev.h"
#include "net_irq.h"
#include "utils.h"

static struct net_dev *devices;

struct net_dev *
net_dev_alloc()
{
	struct net_dev *dev = malloc(sizeof(*dev));
	if (!dev) {
		log_error(strerror(errno));
		return NULL;
	}
	return dev;
}

int
net_dev_register(struct net_dev *dev)
{
	if (dev == NULL)
		return -1;
	static unsigned int index = 0;
	dev->index = index;
	snprintf(dev->name, IFNAMSIZ, "net%d",  index);
	dev->next = devices;
	devices = dev;
	++index;
	log_info("registered, dev=%s, type=%d", dev->name, dev->type);
	return 0;
}

int
net_dev_open(struct net_dev *dev)
{
	if (dev->flags & NET_DEV_FLAG_UP) {
		log_error("already opened, dev=%s", dev->name);
		return -1;
	}
	if (dev->ops->open && dev->ops->open(dev) == -1) {
		log_error("failure, dev=%s", dev->name);
		return -1;
	}
	dev->flags ^= NET_DEV_FLAG_UP;
	log_info("dev=%s, state=%s", dev->name, NET_DEV_STATE(dev->flags));
	return 0;
}


int
net_dev_close(struct net_dev *dev)
{
	if (~dev->flags & NET_DEV_FLAG_UP) {
		log_error("already closed, dev=%s", dev->name);
		return -1;
	}
	if (dev->ops->close && dev->ops->close(dev) == -1) {
		log_error("failure, dev=%s", dev->name);
		return -1;
	}
	dev->flags ^= NET_DEV_FLAG_UP;
	log_info("dev=%s, state=%s", dev->name, NET_DEV_STATE(dev->flags));
	return 0;
}

int
net_dev_output(struct net_dev *dev, void *data, const size_t len, uint16_t type, const void *dst)
{
	if (~dev->flags & NET_DEV_FLAG_UP) {
		log_error("not opened, dev=%s", dev->name);
		return -1;
	}

	if (dev->mtu < len) {
		log_error("size too big, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
		return -1;
	}
	debug_dump(data, len);
	if (dev->ops->transmit(dev, data, len, type, dst) == -1) {
		log_error("device transmit failure, dev=%s, len=%zu", dev->name, len);
		return -1;
	}
	return 0;
}


int
net_input_handler(struct net_dev *dev, void *data, const size_t len) 
{
	log_debug("dev=%s, len=%zu", dev->name, len);
	debug_dump(data, len);
	return 0;
}

int
net_init()
{
	if (irq_init() < 0) {
		return -1;
	}
	log_info("initialized");
	return 0;
}

int
net_run()
{
	if (irq_run() < 0) {
		log_error("irq_run() failure");
		return -1;
	}
	log_debug("open all devices...");
	struct net_dev *dev;
	for (dev = devices; dev; dev = dev->next) {
		net_dev_open(dev);
	}
	log_debug("running...");
	return 0;
}


int
net_shutdown()
{
	irq_shutdown();
	struct net_dev *dev;
	log_debug("close all devices...");
	for (dev = devices; dev; dev = dev->next) {
		net_dev_close(dev);
	}
	log_debug("shutting down");
	return 0;
}

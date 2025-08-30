#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "arp.h"
#include "icmp.h"
#include "ip.h"
#include "net_dev.h"
#include "net_irq.h"
#include "tcp.h"
#include "udp.h"
#include "utils.h"

struct net_protocol
{
	struct net_protocol *next;
	uint16_t type;
	void (*handler) (const uint8_t *data, size_t len, struct net_dev *dev);
	struct queue queue;
};

struct net_protocol_queue_entry
{
	struct net_dev *dev;
	size_t len;
	uint8_t data[];
};

struct net_timer {
    struct net_timer *next;
    struct timeval interval;
    struct timeval last;
    void (*handler)(void);
};

struct net_event {
    struct net_event *next;
    void (*handler)(void *arg);
    void *arg;
};

static struct net_dev *devices;
static struct net_protocol *protocols;
static struct net_timer *timers;
static struct net_event *events;

struct net_dev *
net_dev_alloc()
{
	struct net_dev *dev = calloc(1, sizeof(*dev));
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

struct net_iface *
net_dev_get_iface(struct net_dev *dev, int family)
{
    struct net_iface *entry;

    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == family) {
            return entry;
        }
    }
    return NULL;
}

int
net_input_handler(struct net_dev *dev, void *data, const size_t len, uint16_t type) 
{
	struct net_protocol *prot;
	struct net_protocol_queue_entry *entry;
	for (prot = protocols; prot; prot = prot->next) {
		if (prot->type == type) {
			entry = malloc(sizeof(*entry) + len);
			if (!entry) {
				log_error(strerror(errno));
				return -1;
			}
			entry->dev = dev;
			entry->len = len;
			memcpy(entry + 1, data, len);
			queue_push(&prot->queue, entry);
			log_debug("queue pushed, dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
			debug_dump(data, len);
			irq_raise(INTR_IRQ_SOFTIRQ);
			return 0;
		}
	}
	log_error("unsupported protocol, type=0x%04x", type);
	return -1;
}

int
net_init()
{
	if (irq_init() < 0) {
		log_error("irq_init() failure");
		return -1;
	}
	if (arp_init() < 0) {
		log_error("arp_init() failure");
		return -1;
	}
	if (ip_init() < 0) {
		log_error("ip_init() failure");
		return -1;
	}
	if (icmp_init() == -1) {
		log_error("icmp_init() failure");
		return -1;
	}
	if (udp_init() == -1) {
		log_error("udp_init() failure");
		return -1;
	}
	if (tcp_init() == -1) {
		log_error("tcp_init() failure");
		return -1;
	}
	log_info("initialized");
	return 0;
}

int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_dev *dev))
{
	struct net_protocol *prot;
	for (prot = protocols; prot; prot = prot->next) {
		if (prot->type == type) {
			log_error("protocol already registered, type=0x%04x", type);
			return -1;
		}
	}
	prot = malloc(sizeof(*prot));
	if (!prot) {
		log_error(strerror(errno));
		return -1;
	}
	prot->type = type;
	prot->handler = handler;
	prot->next = protocols;
	queue_init(&prot->queue);
	protocols = prot;
	log_info("registered protocol, type=0x%04x", type);
	return 0;
}

int
net_protocol_handler(void)
{
	struct net_protocol *prot;
	for (prot = protocols; prot; prot = prot->next) {
		struct net_protocol_queue_entry *entry;
		while ((entry = queue_pop(&prot->queue))) {
			log_debug("queue popped (size:%zu), dev=%s, type=0x%04x, len=%zu", prot->queue.size, entry->dev->name, prot->type, entry->len);
			debug_dump((uint8_t *)(entry + 1), entry->len);
			prot->handler((uint8_t *)(entry + 1), entry->len, entry->dev);
			free(entry);
		}
	}
	return 0;
}

int
net_event_subscribe(void (*handler)(void *arg), void *arg)
{
	struct net_event *event;

	event = malloc(sizeof(*event));
	if (!event) {
		log_error(strerror(errno));
		return -1;
	}
	event->handler = handler;
	event->arg = arg;
	event->next = events;
	events = event;
	return 0;
}

int
net_event_handler(void)
{
	struct net_event *event;

	for (event = events; event; event = event->next) {
		event->handler(event->arg);
	}
	return 0;
}

void
net_raise_event()
{
	irq_raise(INTR_IRQ_EVENT);
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

int
net_timer_register(struct timeval interval, void (*handler)(void))
{
	struct net_timer *timer;

	timer = malloc(sizeof(*timer));
	if (!timer) {
		log_error(strerror(errno));
		return -1;
	}
	timer->interval = interval;
	gettimeofday(&timer->last, NULL);
	timer->handler = handler;
	timer->next = timers;
	timers = timer;
	log_info("registered: interval={%d, %d}", interval.tv_sec, interval.tv_usec);
	return 0;
}

int
net_timer_handler(void)
{
	struct net_timer *timer;
	struct timeval now, diff;

	for (timer = timers; timer; timer = timer->next) {
		gettimeofday(&now, NULL);
		timersub(&now, &timer->last, &diff);
		if (timercmp(&timer->interval, &diff, <) != 0) {
			timer->handler();
			timer->last = now;
		}
	}
	return 0;
}

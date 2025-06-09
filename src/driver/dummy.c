#include "dummy.h"
#include "net_dev.h"
#include "net_irq.h"
#include "utils.h"

static int
dummy_transmit(struct net_dev *dev, const uint8_t *data, const size_t len, uint16_t type, const uint8_t *dst)
{
	log_debug("dev=%s, len=%zu", dev->name, len);
	debug_dump(data, len);
	irq_raise(DUM_IRQ);
	return 0;
}

static int
dummy_isr(unsigned int irq, void *dev)
{
	log_debug("irq=%u, dev=%s", irq, ((struct net_dev *)dev)->name);
	return 0;
}

static struct net_dev_ops dum_ops = {
	.transmit = dummy_transmit
};


struct net_dev *
dummy_init()
{
	struct net_dev *dum_dev;
	dum_dev = net_dev_alloc();
	dum_dev->type = NET_DEV_TYPE_DUMMY;
	dum_dev->mtu = DUM_MTU;
	dum_dev->hlen = 0;
	dum_dev->alen = 0;
	dum_dev->ops = &dum_ops;
	if (net_dev_register(dum_dev) == -1) {
		log_error("net_dev registrantion failure");
		return NULL;
	}
	irq_register(DUM_IRQ, dummy_isr, NET_IRQ_SHARED, dum_dev->name, dum_dev);
	log_debug("intialized, dev=%s", dum_dev->name);
	return dum_dev;
}

#include "dummy.h"
#include "utils.h"
#include "net_dev.h"

static int
dummy_transmit(struct net_dev *dev, const uint8_t *data, const size_t len, const uint8_t *dst)
{
	log_debug("dev=%s, len=%zu", dev->name, len);
	debug_dump(data, len);
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
	log_debug("intialized, dev=%s", dum_dev->name);
	return dum_dev;
}

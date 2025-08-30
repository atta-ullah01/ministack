#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "eth_tap.h"
#include "ether.h"
#include "net_dev.h"
#include "net_irq.h"
#include "utils.h"

#define TUN_DEV "/dev/net/tun"

struct eth_tap {
	char name[IFNAMSIZ];
	int fd;
	unsigned int irq;
};

static int
eth_tap_addr(struct net_dev *dev)
{
	int soc;
	struct ifreq ifr = {};

	soc = socket(AF_INET, SOCK_DGRAM, 0);
	if (soc == -1) {
		log_error("socket: %s, dev=%s", strerror(errno), dev->name);
		return -1;
	}
	strncpy(ifr.ifr_name, ((struct eth_tap *)dev->driv)->name, sizeof(ifr.ifr_name)-1);
	if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
		log_error("ioctl(SIOCGIFHWADDR): %s, dev=%s", strerror(errno), dev->name);
		close(soc);
		return -1;
	}
	memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	close(soc);
	return 0;
}

static int
eth_tap_open(struct net_dev *dev)
{
	struct eth_tap *tap;
	struct ifreq ifr = {};

	tap = (struct eth_tap *) dev->driv;
	tap->fd = open(TUN_DEV, O_RDWR);
	if (tap->fd == -1) {
		log_error("open: %s, dev=%s", strerror(errno), dev->name);
		return -1;
	}
	strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name)-1);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) {
		log_error("ioctl(TUNSETIFF): %s, dev=%s", strerror(errno), dev->name);
		close(tap->fd);
		return -1;
	}

	if (fcntl(tap->fd, F_SETOWN, getpid()) == -1) {
		log_error("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
		close(tap->fd);
		return -1;
	}

	if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1) {
		log_error("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
		close(tap->fd);
		return -1;
	}

	if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) {
		log_error("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
		close(tap->fd);
		return -1;
	}
	if (memcmp(dev->addr, ETH_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
		if (eth_tap_addr(dev) == -1) {
			log_error("eth_tap_addr() failure, dev=%s", dev->name);
			close(tap->fd);
			return -1;
		}
	}
	return 0;
}

static int
eth_tap_close(struct net_dev *dev)
{
	return close(((struct eth_tap *)dev->driv)->fd);
}

static ssize_t
eth_tap_write(struct net_dev *dev, const uint8_t *frame, size_t flen)
{
	return write(((struct eth_tap *)dev->driv)->fd, frame, flen);
}

int
eth_tap_transmit(struct net_dev *dev, const uint8_t *buf, size_t len, uint16_t type, const uint8_t *dst)
{
	return eth_transmit_helper(dev, type, buf, len, dst, eth_tap_write);
}

static ssize_t
eth_tap_read(struct net_dev *dev, uint8_t *buf, size_t size)
{
	ssize_t len;

	len = read(((struct eth_tap *)dev->driv)->fd, buf, size);
	if (len <= 0) {
		if (len == -1 && errno != EINTR) {
			log_error("read: %s, dev=%s", strerror(errno), dev->name);
		}
		return -1;
	}
	return len;
}

static int
eth_tap_irq(unsigned int irq, void *id)
{
	struct net_dev *dev;;
	struct pollfd pfd;
	int ret;

	dev = (struct net_dev *)id;
	pfd.fd = ((struct eth_tap *)dev->driv)->fd;
	pfd.events = POLLIN;
	while (1) {
		ret = poll(&pfd, 1, 0);
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			}
			log_error("poll: %s, dev=%s", strerror(errno), dev->name);
			return -1;
		}
		if (ret == 0) {
			/* No frames to input immediately. */
			break;
		}
		eth_input_helper(dev, eth_tap_read);
	}
	return 0;
}

static struct net_dev_ops eth_tap_ops = {
	.open = eth_tap_open,
	.close = eth_tap_close,
	.transmit = eth_tap_transmit,
};

struct net_dev *
eth_tap_init(const char *name, const char *addr)
{
	struct net_dev *dev;
	struct eth_tap *tap;

	dev = net_dev_alloc();
	if (!dev) {
		log_error("net_dev_alloc() failure");
		return NULL;
	}
	eth_setup_helper(dev);
	if (addr) {
		if (eth_addr_pton(addr, dev->addr) == -1) {
			log_error("invalid address, addr=%s", addr);
			return NULL;
		}
	}
	dev->ops = &eth_tap_ops;
	tap = malloc(sizeof(*tap));
	if (!tap) {
		log_error(strerror(errno));
		return NULL;
	}
	strncpy(tap->name, name, sizeof(tap->name)-1);
	tap->fd = -1;
	tap->irq = ETHER_TAP_IRQ;
	dev->driv = tap;
	if (net_dev_register(dev) == -1) {
		log_error("net_dev_register() failure");
		free(tap);
		return NULL;
	}
	irq_register(tap->irq, eth_tap_irq, NET_IRQ_SHARED, dev->name, dev);
	log_info("ethernet device initialized, dev=%s", dev->name);
	return dev;
}

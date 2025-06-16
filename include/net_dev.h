#ifndef NET_DEV_H
#define NET_DEV_H

#include <stdint.h>
#include <stddef.h>

#define IFNAMSIZ		16

#define NET_DEV_TYPE_DUMMY	0x0004
#define NET_DEV_TYPE_NULL	0x0000
#define NET_DEV_TYPE_LOOPBACK	0x0001
#define NET_DEV_TYPE_ETHERNET	0x0002

#define NET_DEV_FLAG_UP		0x0001
#define NET_DEV_FLAG_LOOPBACK	0x0000
#define NET_DEV_FLAG_NEED_ARP	0x0100

#define NET_DEV_ADDR_SZ		16

#define NET_DEV_STATE(x)	x & NET_DEV_FLAG_UP ? "up": "down"

#define NET_IFACE_FAMILY_IPV4	1
#define NET_IFACE_FAMILY_IPV6	2

#define NET_IRQ_SHARED		0x0001

#define NET_PROT_TYPE_IP	0x0800

struct net_dev;

struct net_iface {
    struct net_iface *next;
    struct net_dev *dev;
    int family;
};

struct net_dev {
	struct net_dev *next;
	struct net_iface *ifaces;
	unsigned int index;
	char name[IFNAMSIZ];
	uint16_t type;
	uint16_t mtu;
	uint16_t flags;
	uint16_t hlen;
	uint16_t alen;
	uint8_t addr[NET_DEV_ADDR_SZ];
	union {
		uint8_t peer[NET_DEV_ADDR_SZ];
		uint8_t broadcast[NET_DEV_ADDR_SZ];
	};
	struct net_dev_ops *ops;
	void *driv;
};

struct net_dev_ops {
	int (*open) (struct net_dev *dev);
	int (*close) (struct net_dev *dev);
	int (*transmit) (struct net_dev *dev, const uint8_t *data, const size_t len, uint16_t type, const uint8_t *dst);
};


extern struct net_dev *
net_dev_alloc();

extern int
net_dev_register(struct net_dev *dev);

extern int
net_dev_open(struct net_dev *dev);

extern int
net_dev_close(struct net_dev *dev);

extern struct net_iface *
net_dev_get_iface(struct net_dev *dev, int family);

extern int
net_dev_output(struct net_dev *dev, void *data, const size_t len, uint16_t type, const void *dst);

extern int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_dev *dev));

extern int
net_protocol_handler(void);

extern int
net_input_handler(struct net_dev *dev, void *data, const size_t len, uint16_t type);

extern int
net_run();

extern int
net_shutdown();

extern int
net_init();

#endif

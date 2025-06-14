#ifndef IP
#define IP

#include <stdint.h>

#include "net_dev.h"

#define IP_ADDR_STR_LEN 16
#define IP_VERSION_4	4
#define IP_HDR_SIZE_MIN (5 << 2)

typedef uint32_t ip_addr_t;

struct ip_iface
{
    struct net_iface iface;
    struct ip_iface *next;
    ip_addr_t unicast;
    ip_addr_t netmask;
    ip_addr_t broadcast;
};

extern int
ip_addr_pton(const char *p, ip_addr_t *n);

extern char *
ip_addr_ntop(ip_addr_t n, char *p, size_t len);

extern void
ip_dump(const uint8_t *data, size_t len);

extern struct ip_iface *
ip_iface_alloc(const char *unicast, const char *netmask);

extern int
ip_iface_register(struct net_dev *dev, struct ip_iface *iface);

extern struct ip_iface *
ip_iface_select(ip_addr_t addr);

extern int
ip_init(void);

#endif

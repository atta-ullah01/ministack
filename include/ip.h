#ifndef IP
#define IP

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net_dev.h"

#define IP_PROT_NAME_SIZE_MAX 16

#define IP_PROT_TYPE_ICMP 0x01
#define IP_PROT_TYPE_TCP  0x06
#define IP_PROT_TYPE_UDP  0x11

#define IP_ADDR_STR_LEN		16
#define IP_VERSION_4		4
#define IP_VERSION_6		6

#define IP_HDR_SIZE_MIN		(5 << 2)
#define IP_PAYLOAD_SIZE_MAX	(IP_TOTAL_SIZE_MAX - IP_HDR_SIZE_MIN)
#define IP_TOTAL_SIZE_MAX	UINT16_MAX

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

int
ip_prot_register(const char *name, uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface));


extern ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst);

#endif

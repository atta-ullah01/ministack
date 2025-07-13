#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "arp.h"
#include "ip.h"
#include "net_dev.h"
#include "utils.h"

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

struct ip_hdr
{
	uint8_t ver_len;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t flag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	ip_addr_t src;
	ip_addr_t dst;
	uint8_t options[];
};

struct ip_prot
{
    struct ip_prot *next;
    uint8_t type;
    char name[IP_PROT_NAME_SIZE_MAX];
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

static struct ip_iface *ifaces;
static struct ip_prot *protocols;

int
ip_addr_pton(const char *p, ip_addr_t *n)
{
	uint8_t *oct = (uint8_t *)n;
	int ret;
	ret = sscanf(p, "%hhu.%hhu.%hhu.%hhu", &oct[0], &oct[1], &oct[2], &oct[3]);
	if (ret != 4)
		return -1;
	return 0;
}

char *
ip_addr_ntop(ip_addr_t n, char *p, size_t len)
{
	uint8_t *oct = (uint8_t *)(&n);
	snprintf(p, len, "%d.%d.%d.%d", oct[0], oct[1], oct[2], oct[3]);
	return p;
}

void
ip_dump(const uint8_t *data, size_t len)
{
	struct ip_hdr *hdr;
	uint8_t v, hl, hlen;
	uint16_t total, offset;
	char addr[IP_ADDR_STR_LEN];

	flockfile(stderr);
	hdr = (struct ip_hdr *)data;
	v = (hdr->ver_len & 0xf0) >> 4;
	hl = hdr->ver_len & 0x0f;
	hlen = hl << 2;
	fprintf(stderr, "    ver_len: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->ver_len, v, hl, hlen);
	fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
	total = ntoh16(hdr->tot_len);
	fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
	fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
	offset = ntoh16(hdr->flag_offset);
	fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
	fprintf(stderr, "        ttl: %u\n", hdr->ttl);
	fprintf(stderr, "   protocol: %u\n", hdr->protocol);
	fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->checksum));
	fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
	fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef DEBUG
	hexdump(stderr, (void *)data, len);
#endif
	funlockfile(stderr);
}

struct ip_iface *
ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    iface = malloc(sizeof(*iface));
    if (!iface) {
        log_error(strerror(errno));
        return NULL;
    }
    ((struct net_iface *)iface)->family = NET_IFACE_FAMILY_IPV4;
    if (ip_addr_pton(unicast, &iface->unicast) == -1) {
        log_error("ip_addr_pton() failure, addr=%s", unicast);
        free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        log_error("ip_addr_pton() failure, addr=%s", netmask);
        free(iface);
        return NULL;
    }
    iface->broadcast = (iface->unicast & iface->netmask) | ~iface->netmask;
    return iface;
}

int
ip_iface_register(struct net_dev *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    struct net_iface *entry;
    for (entry = dev->ifaces; entry; entry = entry->next) {
	    if (((struct net_iface *)iface)->family == entry->family) {
		    log_error("already exists, dev=%s, family=%d", dev->name, entry->family);
		    return -1;
	    }
    }
    ((struct net_iface *)iface)->dev = dev;
    ((struct net_iface *)iface)->next = dev->ifaces;
    dev->ifaces = (struct net_iface *)iface;

    iface->next = ifaces;
    ifaces = iface;

    log_info("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s",
        dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
    struct ip_iface *entry;

    for (entry = ifaces; entry; entry = entry->next) {
        if (entry->unicast == addr) {
            return entry;
        }
    }
    return NULL;
}

static void
ip_input(const uint8_t *data, size_t len, struct net_dev *dev)
{
	struct ip_hdr *hdr;
	struct ip_iface *iface;
	uint8_t ver, hlen;
	uint16_t flag_offset, total;

	if (len < IP_HDR_SIZE_MIN) {
		log_error("too short");
		return;
	}
	hdr = (struct ip_hdr *)data;
	ver = hdr->ver_len >> 4;
	if (ver != IP_VERSION_4) {
		log_error("ip version error: v=%u", ver);
		return;
	}
	hlen = (hdr->ver_len & 0x0f) << 2;
	if (len < hlen) {
	    log_error("header length error: hlen=%u, len=%zu", hlen, len);
	    return;
	}
	total = ntoh16(hdr->tot_len);
	if (len < total) {
		log_error("total length error: total=%u, len=%zu", total, len);
		return;
	}
	if (cksum16(data, hlen, 0) != 0) {
		log_error("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->checksum), ntoh16(cksum16((uint8_t *)hdr, hlen, -hdr->checksum)));
		return;
	}
	flag_offset = ntoh16(hdr->flag_offset);
	if (flag_offset & 0x2000 || flag_offset & 0x1fff) {
		log_error("fragments does not support");
		return;
	}

	iface = (struct ip_iface *)net_dev_get_iface(dev, NET_IFACE_FAMILY_IPV4);
	if (!iface) {
		return;
	}
	if (hdr->dst != iface->unicast) {
		if (hdr->dst != iface->broadcast && hdr->dst != IP_ADDR_BROADCAST) {
			return;
		}
	}

	log_debug("dev=%s, len=%zu", dev->name, len);
	ip_dump(data, len);
	for (struct ip_prot *proto = protocols; proto; proto = proto->next) {
		if (proto->type == hdr->protocol) {
			proto->handler((uint8_t *)hdr + hlen, total - hlen, hdr->src, hdr->dst, iface);
			return;
		}
	}
	log_warn("unsupported protocol, type=0x%02x", hdr->protocol);
}

static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
	uint8_t hwaddr[NET_DEV_ADDR_SZ] = {};
	int ret;

	if (((struct net_iface *)iface)->dev->flags & NET_DEV_FLAG_NEED_ARP) {
		if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
			memcpy(hwaddr,((struct net_iface *)iface)->dev->broadcast,((struct net_iface *)iface)->dev->alen);
		} else {
			ret = arp_resolve(NET_IFACE(iface), dst, hwaddr);
			if (ret != ARP_RESOLVE_FOUND) {
				return ret;
			}
		}
	}
	return net_dev_output(((struct net_iface *)iface)->dev, (void *)data, len, NET_PROT_TYPE_IP, hwaddr);
}


static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;
    hlen = sizeof(*hdr);
    hdr->ver_len = (IP_VERSION_4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    total = hlen + len;
    hdr->tot_len = hton16(total);
    hdr->id = hton16(id);
    hdr->flag_offset = hton16(offset);
    hdr->ttl = 0xff;
    hdr->protocol = protocol;
    hdr->checksum = 0;
    hdr->src = src;
    hdr->dst = dst;
    hdr->checksum = hton16(cksum16((uint8_t *)hdr, hlen, 0));
    memcpy(hdr+1, data, len);
    log_debug("dev=%s, iface=%s, protocol=0x%02x, len=%u",
        ((struct net_iface *)iface)->dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, dst);
}

ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
	static uint16_t id = 127;
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	struct ip_iface *iface;
	char addr[IP_ADDR_STR_LEN];

	for (iface = ifaces; src != IP_ADDR_ANY && iface; iface = iface->next) {
		if (iface->unicast == src) {
			break;
		}
	}
	if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST) {
		log_error("source address is required for broadcast addresses");
		return -1;
	}
	if (src != IP_ADDR_ANY && (!iface || src != iface->unicast)) {
		log_error("unable to output with specified source address, addr=%s", ip_addr_ntop(src, addr, sizeof(addr)));
		return -1;
	}
	if (((struct net_iface *)iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
		log_error("too long, dev=%s, mtu=%u, tatal=%zu",
				((struct net_iface *)iface)->dev->name, ((struct net_iface *)iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
		return -1;
	}

	pthread_mutex_lock(&mutex);
	++id;
	pthread_mutex_unlock(&mutex);

	if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1) {
		log_error("ip_output_core() failure");
		return -1;
	}
	return len;
}

int
ip_prot_register(const char *name, uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface))
{
    struct ip_prot *entry;

    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            log_error("already exists, type=%s(0x%02x), exist=%s(0x%02x)", name, type, entry->name, entry->type);
            return -1;
        }
    }
    entry = malloc(sizeof(*entry));
    if (!entry) {
        log_error(strerror(errno));
        return -1;
    }
    strncpy(entry->name, name, IP_PROT_NAME_SIZE_MAX - 1);
    entry->type = type;
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;
    log_info("registered, type=%s(0x%02x)", entry->name, entry->type);
    return 0;
}


int
ip_init(void)
{
	if (net_protocol_register(NET_PROT_TYPE_IP, ip_input) < 0) {
		log_error("net_protocol_register() failure");
		return -1;
	}
	log_info("protocol registered, type=0x%04x", NET_PROT_TYPE_IP);
	return 0;
}

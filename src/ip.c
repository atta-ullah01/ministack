#include <stdio.h>

#include "ip.h"
#include "net_dev.h"
#include "utils.h"

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

static void
ip_input(const uint8_t *data, size_t len, struct net_dev *dev)
{
	struct ip_hdr *hdr;
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
	log_debug("dev=%s, len=%zu", dev->name, len);
	ip_dump(data, len);
}

int
ip_init(void)
{
	if (net_protocol_register(NET_PROT_TYPE_IP, ip_input) < 0) {
		log_error("net_protocol_register failure");
		return -1;
	}
	log_info("protocol registered, type=0x%04x", NET_PROT_TYPE_IP);
	return 0;
}

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "utils.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE    0
#define UDP_PCB_STATE_OPEN    1
#define UDP_PCB_STATE_CLOSING 2

#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct udp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

struct udp_pcb {
    int state;
    struct ip_endpoint local;
    struct queue queue;
    int wc;
};

struct udp_queue_entry {
    struct ip_endpoint foreign;
    uint16_t len;
    uint8_t data[];
};

static pthread_mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

static void
udp_dump(const uint8_t *data, size_t len)
{
	struct udp_hdr *hdr;

	flockfile(stderr);
	hdr = (struct udp_hdr *)data;
	fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
	fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
	fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
	fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef DEBUG
	hexdump(stderr, data, len);
#endif
	funlockfile(stderr);
}

static struct udp_pcb *
udp_pcb_alloc(void)
{
	struct udp_pcb *pcb;

	for (pcb = pcbs; pcb < (pcbs + UDP_PCB_SIZE); pcb++) {
		if (pcb->state == UDP_PCB_STATE_FREE) {
			pcb->state = UDP_PCB_STATE_OPEN;
			return pcb;
		}
	}
	return NULL;
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
	struct queue_node *entry;

	if (pcb->wc) {
		pcb->state = UDP_PCB_STATE_CLOSING;
		return;
	}

	pcb->state = UDP_PCB_STATE_FREE;
	pcb->local.addr = IP_ADDR_ANY;
	pcb->local.port = 0;
	while (1) {
		entry = queue_pop(&pcb->queue);
		if (!entry) {
			break;
		}
		free(entry);
	}
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
	struct udp_pcb *pcb;

	for (pcb = pcbs; pcb < (pcbs + UDP_PCB_SIZE); pcb++) {
		if (pcb->state == UDP_PCB_STATE_OPEN) {
			if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port) {
				return pcb;
			}
		}
	}
	return NULL;
}

static struct udp_pcb *
udp_pcb_get(int id)
{
	struct udp_pcb *pcb;

	if (id < 0 || id >= UDP_PCB_SIZE) {
		return NULL;
	}
	pcb = &pcbs[id];
	if (pcb->state != UDP_PCB_STATE_OPEN) {
		return NULL;
	}
	return pcb;
}

static int
udp_pcb_id(struct udp_pcb *pcb)
{
	return (int)(pcb - pcbs);
}


static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
	struct pseudo_hdr pseudo;
	uint16_t psum = 0;
	struct udp_hdr *hdr;
	char addr1[IP_ADDR_STR_LEN];
	char addr2[IP_ADDR_STR_LEN];
	struct udp_pcb *pcb;
	struct udp_queue_entry *entry;


	if (len < sizeof(*hdr)) {
		log_error("too short");
		return;
	}
	hdr = (struct udp_hdr *)data;
	if (len != ntoh16(hdr->len)) {
		log_error("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
		return;
	}
	pseudo.src = src;
	pseudo.dst = dst;
	pseudo.zero = 0;
	pseudo.protocol = IP_PROT_TYPE_UDP;
	pseudo.len = hton16(len);
	psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
	if (cksum16((uint16_t *)hdr, len, psum) != 0) {
		log_error("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
		return;
	}
	log_debug("%s:%d => %s:%d, len=%zu (payload=%zu)",
			ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
			ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
			len, len - sizeof(*hdr));
	udp_dump(data, len);

	pthread_mutex_lock(&mutex);
	pcb = udp_pcb_select(dst, hdr->dst);
	if (!pcb) {
		pthread_mutex_unlock(&mutex);
		return;
	}
	entry = malloc(sizeof(*entry) + (len - sizeof(*hdr)));
	if (!entry) {
		pthread_mutex_unlock(&mutex);
		log_error(strerror(errno));
		return;
	}
	entry->foreign.addr = src;
	entry->foreign.port = hdr->src;
	entry->len = len - sizeof(*hdr);
	memcpy(entry->data, hdr+1, entry->len);
	if (!queue_push(&pcb->queue, entry)) {
		pthread_mutex_unlock(&mutex);
		log_error("queue_push() failure");
		return;
	}
	log_debug("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
	pthread_mutex_unlock(&mutex);
}

ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const  uint8_t *data, size_t len)
{
	uint8_t buf[IP_PAYLOAD_SIZE_MAX];
	struct udp_hdr *hdr;
	struct pseudo_hdr pseudo;
	uint16_t total, psum = 0;
	char ep1[IP_ENDPOINT_STR_LEN];
	char ep2[IP_ENDPOINT_STR_LEN];

	if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
		log_error("too long");
		return -1;
	}
	hdr = (struct udp_hdr *)buf;
	hdr->src = src->port;
	hdr->dst = dst->port;
	total = sizeof(*hdr) + len;
	hdr->len = hton16(total);
	hdr->sum = 0;
	memcpy(hdr + 1, data, len);
	pseudo.src = src->addr;
	pseudo.dst = dst->addr;
	pseudo.zero = 0;
	pseudo.protocol = IP_PROT_TYPE_UDP;
	pseudo.len = hton16(total);
	psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
	hdr->sum = cksum16((uint16_t *)hdr, total, psum);
	log_debug("%s => %s, len=%zu (payload=%zu)",
			ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
	udp_dump((uint8_t *)hdr, total);
	if (ip_output(IP_PROT_TYPE_UDP, (uint8_t *)hdr, total, src->addr, dst->addr) == -1) {
		log_error("ip_output() failure");
		return -1;
	}
	return len;
}

int
udp_init(void)
{
	if (ip_prot_register(IP_PROT_TYPE_UDP, udp_input) == -1) {
		log_error("ip_prot_register() failure");
		return -1;
	}
	return 0;
}

int
udp_open(void)
{
	struct udp_pcb *pcb;
	int id;

	pthread_mutex_lock(&mutex);
	pcb = udp_pcb_alloc();
	if (!pcb) {
		log_error("udp_pcb_alloc() failure");
		pthread_mutex_unlock(&mutex);
		return -1;
	}
	id = udp_pcb_id(pcb);
	pthread_mutex_unlock(&mutex);
	return id;
}

int
udp_close(int id)
{
	struct udp_pcb *pcb;

	pthread_mutex_lock(&mutex);
	pcb = udp_pcb_get(id);
	if (!pcb) {
		log_error("pcb not found, id=%d", id);
		pthread_mutex_unlock(&mutex);
		return -1;
	}
	udp_pcb_release(pcb);
	pthread_mutex_unlock(&mutex);
	return 0;
}

int
udp_bind(int id, struct ip_endpoint *local)
{
	struct udp_pcb *pcb, *exist;
	char ep1[IP_ENDPOINT_STR_LEN];
	char ep2[IP_ENDPOINT_STR_LEN];

	pthread_mutex_lock(&mutex);
	pcb = udp_pcb_get(id);
	if (!pcb) {
		log_error("pcb not found, id=%d", id);
		log_mutex_unlock(&mutex);
		return -1;
	}
	exist = udp_pcb_select(local->addr, local->port);
	if (exist) {
		log_error("already in use, id=%d, want=%s, exist=%s",
				id, ip_endpoint_ntop(local, ep1, sizeof(ep1)), ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
		pthread_mutex_unlock(&mutex);
		return -1;
	}
	pcb->local = *local;
	log_debug("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
	pthread_mutex_unlock(&mutex);
	return 0;
}

ssize_t
udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign)
{
	struct udp_pcb *pcb;
	struct ip_endpoint local;
	struct ip_iface *iface;
	char addr[IP_ADDR_STR_LEN];
	uint32_t p;

	pthread_mutex_lock(&mutex);
	pcb = udp_pcb_get(id);
	if (!pcb) {
		log_error("pcb not found, id=%d", id);
		pthread_mutex_unlock(&mutex);
		return -1;
	}
	local.addr = pcb->local.addr;
	if (local.addr == IP_ADDR_ANY) {
		iface = ip_route_get_iface(foreign->addr);
		if (!iface) {
			log_error("iface not found that can reach foreign address, addr=%s",
					ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
			pthread_mutex_unlock(&mutex);
			return -1;
		}
		local.addr = iface->unicast;
		log_debug("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
	}
	if (!pcb->local.port) {
		for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
			if (!udp_pcb_select(local.addr, hton16(p))) {
				pcb->local.port = hton16(p);
				log_debug("dinamic assign local port, port=%d", p);
				break;
			}
		}
		if (!pcb->local.port) {
			log_debug("failed to dinamic assign local port, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
			pthread_mutex_unlock(&mutex);
			return -1;
		}
	}
	local.port = pcb->local.port;
	pthread_mutex_unlock(&mutex);
	return udp_output(&local, foreign, data, len);
}

ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign)
{
	struct udp_pcb *pcb;
	struct udp_queue_entry *entry;
	ssize_t len;

	pthread_mutex_lock(&mutex);
	pcb = udp_pcb_get(id);
	if (!pcb) {
		log_error("pcb not found, id=%d", id);
		pthread_mutex_unlock(&mutex);
		return -1;
	}
	while (1) {
		entry = queue_pop(&pcb->queue);
		if (entry) {
			break;
		}
		pcb->wc++;
		pthread_mutex_unlock(&mutex);
		sleep(1);
		pthread_mutex_lock(&mutex);
		pcb->wc--;
		if (pcb->state == UDP_PCB_STATE_CLOSING) {
			log_debug("closed");
			udp_pcb_release(pcb);
			pthread_mutex_unlock(&mutex);
			return -1;
		}
	}
	pthread_mutex_unlock(&mutex);
	if (foreign) {
		*foreign = entry->foreign;
	}
	len = entry->len;
	if (len > size)
		len = size;

	memcpy(buf, entry->data, len);
	free(entry);
	return len;
}

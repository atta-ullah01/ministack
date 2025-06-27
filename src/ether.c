#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ether.h"
#include "net_dev.h"
#include "utils.h"

const uint8_t ETH_ADDR_ANY[ETHER_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t ETH_ADDR_BROADCAST[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void
eth_dump(const uint8_t *frame, size_t flen)
{
    struct eth_hdr *hdr;
    char addr[ETHER_ADDR_STR_LEN];

    hdr = (struct eth_hdr *)frame;
    flockfile(stderr);
    fprintf(stderr, "        src: %s\n", eth_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", eth_addr_ntop(hdr->dst, addr, sizeof(addr)));
    fprintf(stderr, "       type: 0x%04x (%s)\n", ntoh16(hdr->type), eth_type_ntoa(hdr->type));
#ifdef DEBUG
    hexdump(stderr, frame, flen);
#endif
    funlockfile(stderr);
}

char *
eth_addr_ntop(const uint8_t *n, char *p, size_t size)
{
    if (!n || !p)
        return NULL;

    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

int
eth_addr_pton(const char *p, uint8_t *n)
{
    int index;
    char *ep;
    long val;

    if (!p || !n) {
        return -1;
    }
    for (index = 0; index < ETHER_ADDR_LEN; index++) {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHER_ADDR_LEN - 1 && *ep != ':')) {
            break;
        }
        n[index] = (uint8_t)val;
        p = ep + 1;
    }
    if (index != ETHER_ADDR_LEN || *ep != '\0') {
        return -1;
    }
    return 0;
}

const char *
eth_type_ntoa(uint16_t type)
{
    switch (ntoh16(type)) {
    case ETHER_TYPE_IP:
        return "IP";
    case ETHER_TYPE_ARP:
        return "ARP";
    case ETHER_TYPE_IPV6:
        return "IPv6";
    }
    return "UNKNOWN";
}


int
eth_transmit_helper(struct net_dev *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst, ssize_t (*callback)(struct net_dev *dev, const uint8_t *data, size_t len))
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX] = {};
    struct eth_hdr *hdr;
    size_t flen, pad = 0;

    hdr = (struct eth_hdr *)frame;
    memcpy(hdr->dst, dst, ETHER_ADDR_LEN);
    memcpy(hdr->src, dev->addr, ETHER_ADDR_LEN);
    hdr->type = hton16(type);
    memcpy(hdr + 1, data, len);
    if (len < ETHER_PAYLOAD_SIZE_MIN) {
        pad = ETHER_PAYLOAD_SIZE_MIN - len;
    }
    flen = sizeof(*hdr) + len + pad;
    log_debug("dev=%s, type=%s(0x%04x), len=%zu", dev->name, eth_type_ntoa(hdr->type), type, flen);
    eth_dump(frame, flen);
    return callback(dev, frame, flen) == (ssize_t)flen ? 0 : -1;
}


int
eth_input_helper(struct net_dev *dev, eth_input_func_t callback)
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX];
    ssize_t flen;
    struct eth_hdr *hdr;
    uint16_t type;

    flen = callback(dev, frame, sizeof(frame));
    if (flen < (ssize_t)sizeof(*hdr)) {
        log_error("too short");
        return -1;
    }
    hdr = (struct eth_hdr *)frame;
    if (memcmp(dev->addr, hdr->dst, ETHER_ADDR_LEN) != 0) {
        if (memcmp(ETH_ADDR_BROADCAST, hdr->dst, ETHER_ADDR_LEN) != 0) {
            /* for other host */
            return -1;
        }
    }
    type = ntoh16(hdr->type);
    log_debug("dev=%s, type=0x%04x, len=%zd", dev->name, type, flen);
    eth_dump(frame, flen);
    return net_input_handler(dev, (uint8_t *)(hdr+1), flen - sizeof(*hdr), type);
}

void
eth_setup_helper(struct net_dev *dev)
{
    dev->type = NET_DEV_TYPE_ETHERNET;
    dev->mtu = ETHER_PAYLOAD_SIZE_MAX;
    dev->flags = (NET_DEV_FLAG_BROADCAST | NET_DEV_FLAG_NEED_ARP);
    dev->hlen = ETHER_HDR_SIZE;
    dev->alen = ETHER_ADDR_LEN;
    memcpy(dev->broadcast, ETH_ADDR_BROADCAST, ETHER_ADDR_LEN);
}

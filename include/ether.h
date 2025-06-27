#ifndef ETHER_H
#define ETHER_H

#include <stdint.h>
#include <stdio.h>
#include <sys/file.h>

#include "net_dev.h"

#define ETHER_ADDR_LEN		6
#define ETHER_ADDR_STR_LEN	18

#define ETHER_HDR_SIZE		14
#define ETHER_FRAME_SIZE_MIN   	60 /* without FCS */
#define ETHER_FRAME_SIZE_MAX 	1514 /* without FCS */
#define ETHER_PAYLOAD_SIZE_MIN 	(ETHER_FRAME_SIZE_MIN - ETHER_HDR_SIZE)
#define ETHER_PAYLOAD_SIZE_MAX 	(ETHER_FRAME_SIZE_MAX - ETHER_HDR_SIZE)

#define ETHER_TYPE_IP  		0x0800
#define ETHER_TYPE_ARP  	0x0806
#define ETHER_TYPE_IPV6 	0x86dd

typedef ssize_t (*eth_transmit_func_t)(struct net_dev *dev, const uint8_t *data, size_t len);
typedef ssize_t (*eth_input_func_t)(struct net_dev *dev, uint8_t *buf, size_t size);

struct eth_hdr {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type;
};

extern const uint8_t ETH_ADDR_ANY[ETHER_ADDR_LEN];
extern const uint8_t ETH_ADDR_BROADCAST[ETHER_ADDR_LEN];

extern char *
eth_addr_ntop(const uint8_t *n, char *p, size_t size);

extern int
eth_addr_pton(const char *p, uint8_t *n);

extern const char *
eth_type_ntoa(uint16_t type);

extern void
eth_dump(const uint8_t *frame, size_t flen);

extern void
eth_setup_helper(struct net_dev *dev);

extern int
eth_transmit_helper(struct net_dev *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst, ssize_t (*callback)(struct net_dev *dev, const uint8_t *data, size_t len));

extern int
eth_input_helper(struct net_dev *dev, eth_input_func_t callback);
#endif

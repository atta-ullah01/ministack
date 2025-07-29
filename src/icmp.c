#include <stddef.h>
#include <stdint.h>

#include "icmp.h"
#include "ip.h"
#include "utils.h"

static void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    log_debug("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);

    debug_dump((void *)data, len);
}

int
icmp_init(void)
{
	if (ip_prot_register(IP_PROT_TYPE_ICMP, icmp_input) < 0) {
		log_error("ip_prot_register() failure");
		return -1;
	}
	return 0;
}

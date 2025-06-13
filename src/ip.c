#include "ip.h"
#include "net_dev.h"
#include "utils.h"

static void
ip_input(const uint8_t *data, size_t len, struct net_dev *dev)
{
	log_debug("dev=%s, len=%zu", dev->name, len);
	debug_dump(data, len);
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

#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "ip.h"
#include "loopback.h"
#include "net_dev.h"
#include "test.h"
#include "utils.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
	(void)s;
	terminate = 1;
}

static int
setup(void)
{
	struct net_dev *dev;
	struct ip_iface *iface;

	signal(SIGINT, on_signal);
	if (net_init() == -1) {
		log_error("net_init() failure");
		return -1;
	}
	dev = loopback_init();
	if (!dev) {
		log_error("loopback_init() failure");
		return -1;
	}
	iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
	if (!iface) {
		log_error("ip_iface_alloc() failure");
		return -1;
	}
	if (ip_iface_register(dev, iface) == -1) {
		log_error("ip_iface_register() failure");
		return -1;
	}
	if (net_run() == -1) {
		log_error("net_run() failure");
		return -1;
	}
	return 0;
}

static void
cleanup(void)
{
	net_shutdown();
}

int
main(int argc, char *argv[])
{
	ip_addr_t src, dst;
	size_t offset = IP_HDR_SIZE_MIN;

	if (setup() == -1) {
		log_error("setup() failure");
		return -1;
	}
	ip_addr_pton(LOOPBACK_IP_ADDR, &src);
	dst = src;
	while (!terminate) {
		if (ip_output(1, test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
			log_error("ip_output() failure");
			break;
		}
		sleep(1);
	}
	cleanup();
	return 0;
}

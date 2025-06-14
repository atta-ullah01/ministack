#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "ip.h"
#include "loopback.h"
#include "net_dev.h"
#include "test.h"
#include "utils.h"

bool terminate = 0;
void on_signal(int signum) {
	net_shutdown();
	terminate = 1;
}

int
main(int argc, char *argv[])
{
	signal(SIGINT, on_signal);
	struct net_dev *dev;
	net_init();
	dev = loopback_init();
	if (!dev) {
		return -1;
	}
	if (net_run() == -1) {
		log_error("net_run() failure");
		return -1;
	}

	struct ip_iface *iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
	ip_iface_register(dev, iface);

	while (!terminate) {
		if (net_dev_output(dev, (void *)test_data, sizeof(test_data), NET_PROT_TYPE_IP, NULL) == -1) {
			log_error("net_dev_output() failure");
			break;
		}

		sleep(1);
	}
	net_shutdown();
}


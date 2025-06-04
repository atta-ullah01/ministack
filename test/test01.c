#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "dummy.h"
#include "net_dev.h"
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
	dev = dummy_init();
	if (!dev) {
		return -1;
	}
	if (net_run() == -1) {
		log_error("net_run() failure");
		return -1;
	}

	char data[] = "hello world";
	while (!terminate) {
		if (net_dev_output(dev, data, sizeof(data), NULL) == -1) {
			log_error("net_dev_output() failure");
			break;
		}
		sleep(1);
	}
	net_shutdown();
}

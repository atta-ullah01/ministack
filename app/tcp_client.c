#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "utils.h"
#include "net_dev.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "sock.h"

#include "driver/loopback.h"
#include "driver/eth_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_raise_event();
    close(0);
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
    dev = eth_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        log_error("eth_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        log_error("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        log_error("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        log_error("ip_route_set_default_gateway() failure");
        return -1;
    }
    if (net_run() == -1) {
        log_error("net_run() failure");
        return -1;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int opt, soc;
    long int port;
    struct sockaddr_in local = { .sin_family=AF_INET }, foreign;
    uint8_t buf[1024];

    /*
     * Parse command line parameters
     */
    while ((opt = getopt(argc, argv, "s:p:")) != -1) {
        switch (opt) {
        case 's':
            if (ip_addr_pton(optarg, &local.sin_addr) == -1) {
                log_error("ip_addr_pton() failure, addr=%s", optarg);
                return -1;
            }
            break;
        case 'p':
            port = strtol(optarg, NULL, 10);
            if (port < 0 || port > UINT16_MAX) {
                log_error("invalid port, port=%s", optarg);
                return -1;
            }
            local.sin_port = hton16(port);
            break;
        default:
            fprintf(stderr, "Usage: %s [-s local_addr] [-p local_port] foreign_addr:port\n", argv[0]);
            return -1;
        }
    }
    if (argc - optind != 1) {
        fprintf(stderr, "Usage: %s [-s local_addr] [-p local_port] foreign_addr:port\n", argv[0]);
        return -1;
    }
    if (sockaddr_pton(argv[optind], (struct sockaddr *)&foreign, sizeof(foreign)) == -1) {
        log_error("sockaddr_pton() failure, %s", argv[optind]);
        return -1;
    }
    /*
     * Setup protocol stack
     */
    if (setup() == -1) {
        log_error("setup() failure");
        return -1;
    }
    /*
     *  Application Code
     */
    soc = sock_open(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (soc == -1) {
        log_error("sock_open() failure");
        return -1;
    }
    if (local.sin_port) {
        if (sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
            log_error("sock_bind() failure");
            return -1;
        }
    }
    if (sock_connect(soc, (struct sockaddr *)&foreign, sizeof(foreign)) == -1) {
        log_error("sock_connect() failure");
        return -1;
    }
    log_info("connection established");
    while (!terminate) {
        if (!fgets((char *)buf, sizeof(buf), stdin)) {
            break;
        }
        if (sock_send(soc, buf, strlen((char *)buf)) == -1) {
            log_error("sock_send() failure");
            break;
        }
    }
    sock_close(soc);
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

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
    int soc, acc;
    long int port;
    struct sockaddr_in local = { .sin_family=AF_INET }, foreign;
    int foreignlen;
    char addr[SOCKADDR_STR_LEN];
    uint8_t buf[1024];
    ssize_t ret;

    /*
     * Parse command line parameters
     */
    switch (argc) {
    case 3:
        if (ip_addr_pton(argv[argc-2], &local.sin_addr) == -1) {
            log_error("ip_addr_pton() failure, addr=%s", optarg);
            return -1;
        }
        /* fall through */
    case 2:
        port = strtol(argv[argc-1], NULL, 10);
        if (port < 0 || port > UINT16_MAX) {
            log_error("invalid port, port=%s", optarg);
            return -1;
        }
        local.sin_port = hton16(port);
        break;
    default:
        fprintf(stderr, "Usage: %s [addr] port\n", argv[0]);
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
    if (sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
        log_error("sock_bind() failure");
        return -1;
    }
    if (sock_listen(soc, 1) == -1) {
        log_error("sock_listen() failure");
        return -1;
    }
    foreignlen = sizeof(foreignlen);
    acc = sock_accept(soc, (struct sockaddr *)&foreign, &foreignlen);
    if (acc == -1) {
        log_error("sock_accept() failure");
        return -1;
    }
    log_info("connection accepted, foreign=%s", sockaddr_ntop((struct sockaddr *)&foreign, addr, sizeof(addr)));
    while (!terminate) {
        ret = sock_recv(acc, buf, sizeof(buf));
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            log_error("sock_recv() failure");
            break;
        }
        if (ret == 0) {
            log_debug("connection closed");
            break;
        }
        log_info("%zu bytes received", ret);
        hexdump(stderr, buf, ret);
        if (sock_send(acc, buf, ret) == -1) {
            log_error("sock_send() failure");
            break;
        }
    }
    sock_close(acc);
    sock_close(soc);
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}

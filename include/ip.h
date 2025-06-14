#ifndef IP
#define IP

#include <stdint.h>

#define IP_ADDR_STR_LEN 16
#define IP_VERSION_4	4
#define IP_HDR_SIZE_MIN (5 << 2)

typedef uint32_t ip_addr_t;

int
ip_init(void);

#endif

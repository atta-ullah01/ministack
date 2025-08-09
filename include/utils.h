#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdint.h>

#define timeval_add_usec(x, y)         \
    do {                               \
        (x)->tv_sec += y / 1000000;    \
        (x)->tv_usec += y % 1000000;   \
        if ((x)->tv_usec >= 1000000) { \
            (x)->tv_sec += 1;          \
            (x)->tv_usec -= 1000000;   \
        }                              \
    } while(0);

#define timespec_add_nsec(x, y)           \
    do {                                  \
        (x)->tv_sec += y / 1000000000;    \
        (x)->tv_nsec += y % 1000000000;   \
        if ((x)->tv_nsec >= 1000000000) { \
            (x)->tv_sec += 1;             \
            (x)->tv_nsec -= 1000000000;   \
        }                                 \
    } while(0);

#define log_error(...)  log_print(stderr, 'E', __FILE__, __func__, __LINE__, __VA_ARGS__)
#define log_warn(...)	log_print(stderr, 'W', __FILE__, __func__, __LINE__, __VA_ARGS__)
#define log_info(...)	log_print(stderr, 'I', __FILE__, __func__, __LINE__, __VA_ARGS__)
#define log_debug(...)	log_print(stderr, 'D', __FILE__, __func__, __LINE__, __VA_ARGS__)

#ifdef DEBUG
#define debug_dump(...) hexdump(stderr, __VA_ARGS__)
#else
#define debug_dump(...)
#endif

extern int
log_print(FILE *stream, char level, const char *file, const char *func, int line, const char*, ...); 

extern void
hexdump(FILE *stream, void *data, size_t len);

struct queue_node;

struct queue
{
	struct queue_node *head;
	struct queue_node *tail;
	size_t size;
};

extern void
queue_init(struct queue *que);

extern void
queue_push(struct queue *que, void *data);

extern void *
queue_pop(struct queue *que);

extern void *
queue_peek(struct queue *que);

void
queue_foreach(struct queue *queue, void (*func)(void *arg, void *data), void *arg);

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

extern uint16_t
hton16(uint16_t h);

extern uint16_t
ntoh16(uint16_t n);

extern uint32_t
hton32(uint32_t h);

extern uint32_t
ntoh32(uint32_t n);

extern uint16_t
cksum16(const uint8_t *data, uint16_t bytecount, uint32_t init);

#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "utils.h"

int
log_print(FILE *stream, const char level, const char *file, const char *func, const int line, const char *fmt, ...)
{
	struct timeval tv;
	struct tm tim;
	char timestamp[32];
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tim);
	strftime(timestamp, (size_t)sizeof(timestamp), "%T", &tim);

	flockfile(stream);
	int n = 0;
	n += fprintf(stream, "%s.%03d [%c] %s:", timestamp, (int)tv.tv_usec / 1000, level, func);
	va_list va;
	va_start(va, fmt);
	n += vfprintf(stream, fmt, va);
	va_end(va);
	n += fprintf(stream, " (%s:%d)\n", file, line);
	funlockfile(stream);
	return n;
}


void
hexdump(FILE *stream, void *data, size_t len)
{
	unsigned char *ptr = (unsigned char *)data;
	flockfile(stream);
	fprintf(stream, "+------+-------------------------------------------------+------------------+\n");
	for (int i = 0; i < (int)len; i += 16) {
		fprintf(stream, "| %04x | ", i);
		for (int j = 0; j < 16; ++j)
			if (i + j < (int)len)
				fprintf(stream, "%02x ", ptr[i + j]); 
			else
				fprintf(stream, "   ");
		fprintf(stream, "| ");
		for (int j = 0; j < 16; ++j) {
			if (i + j < (int)len) {
				if (isascii(ptr[i + j]) && isprint(ptr[i + j]))
					fprintf(stream, "%c", ptr[i + j]);
				else
					fprintf(stream, ".");
			} else {
				fprintf(stream, " ");
			}
		}
		fprintf(stream, " |\n");
	}
	fprintf(stream, "+------+-------------------------------------------------+------------------+\n");
	funlockfile(stream);
}



struct queue_node
{
	struct queue_node *next;
	void *data;
};

void queue_init(struct queue *que)
{
	que->head = NULL;
	que->tail = NULL;
	que->size = 0;
}

void queue_push(struct queue *que, void *data)
{
	struct queue_node *entry = malloc(sizeof(*entry));
	entry->data = data;
	entry->next = NULL;
	if (que->size == 0) {
		que->head = entry;
		que->tail = entry;
	} else {
		que->tail->next = entry;
		que->tail = entry;
	}
	++que->size;
}

void *queue_pop(struct queue *que) {
	if (que->size == 0)
		return NULL;
	struct queue_node *old_head = que->head;
	void *data = old_head->data;
	if (que->size == 1) {
		que->head = NULL;
		que->tail = NULL;
	} else {
		que->head = que->head->next;
	}
	free(old_head);
	--que->size;
	return data;
}

void *queue_peek(struct queue *que)
{
	if (que->size == 0)
		return NULL;
	return que->head->data;
}

void
queue_foreach(struct queue *queue, void (*func)(void *arg, void *data), void *arg)
{
    struct queue_node *entry;

    if (!queue || !func) {
        return;
    }
    for (entry = queue->head; entry; entry = entry->next) {
        func(arg, entry->data);
    }
}

static int
endian()
{
	uint32_t x = 1;
	if (*(uint8_t *)&x)
		return LITTLE_ENDIAN;
	else
		return BIG_ENDIAN;
}

uint16_t
hton16(uint16_t h)
{
	if (endian() == LITTLE_ENDIAN)
		return (h & 0xff) << 8 | (h & 0xff00) >> 8;
	return h;
}

uint16_t
ntoh16(uint16_t n)
{
	if (endian() == LITTLE_ENDIAN)
		return (n & 0xff) << 8 | (n & 0xff00) >> 8;
	return n;
}

uint32_t
hton32(uint32_t h)
{
	if (endian() == LITTLE_ENDIAN)
		return (h & 0xff) << 24 | (h & 0xff00) << 8 | (h & 0xff0000) >> 8 | (h & 0xff000000) >> 24;
	else
		return h;
}

uint32_t
ntoh32(uint32_t n)
{
	if (endian() == LITTLE_ENDIAN)
		return (n & 0xff) << 24 | (n & 0xff00) << 8 | (n & 0xff0000) >> 8 | (n & 0xff000000) >> 24;
	else
		return n;

}

uint16_t
cksum16(const uint8_t *data, uint16_t bytecount, uint32_t init)
{
    uint32_t sum = init;

    while (bytecount > 1) {
        sum += ntoh16(*(uint16_t *)data);
        data += 2;
        bytecount -= 2;
    }
    if (bytecount) {
        sum += (uint32_t)*data << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~(uint16_t)sum;
}

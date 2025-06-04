#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>

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
	n += fprintf(stream, fmt, va);
	va_end(va);
	n += fprintf(stream, " (%s:%d)\n", file, line);
	funlockfile(stream);
	return n;
}


void
hexdump(FILE *stream, void *data, size_t len)
{
	char *ptr = (char *)data;
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

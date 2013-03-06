#include "util.h"

#include <stdio.h>
#include <stdlib.h>

void die(const char *format, ...) {
	va_list args;
	va_start(args, format);
	fputs("\x1b[31;1mDIE\x1b[0m:   ", stderr);
	vfprintf(stderr, format, args);
	va_end(args);
	abort();
}

const char *names[] = {
	[LOG_ERROR] = "\x1b[31mERROR\x1b[0m: ",
	[LOG_WARN] =  "\x1b[35mWARN\x1b[0m:  ",
	[LOG_INFO] =  "\x1b[34mINFO\x1b[0m:  ",
	[LOG_DEBUG] = "DEBUG: ",
	[LOG_DEBUG_VERBOSE] = "DEBVE: "
};

void ulog_internal(enum log_level log_level, const char *format, va_list *args) {
	(void) log_level; // Currently ignored
	fputs(names[log_level], stderr);
	vfprintf(stderr, format, *args);
}

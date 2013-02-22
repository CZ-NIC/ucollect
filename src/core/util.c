#include "util.h"

#include <stdio.h>
#include <stdlib.h>

void die(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(1);
}

void ulog_internal(enum log_level log_level, const char *format, va_list *args) {
	(void) log_level; // Currently ignored
	vfprintf(stderr, format, *args);
}

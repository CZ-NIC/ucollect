#include "util.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

void die(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(1);
}

void ulog(enum log_level log_level, const char *format, ...) {
	(void) log_level; // Currently ignored
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

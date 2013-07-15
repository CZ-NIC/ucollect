#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

void die(const char *format, ...) {
	va_list args;
	va_start(args, format);
	va_list copy;
	va_copy(copy, args);
	fputs("\x1b[31;1mDIE\x1b[0m:   ", stderr);
	vfprintf(stderr, format, args);
	vsyslog(LOG_MAKEPRI(LOG_DAEMON, LOG_CRIT), format, copy);
	va_end(copy);
	va_end(args);
	abort();
}

const char *names[] = {
	[LLOG_ERROR] = "\x1b[31mERROR\x1b[0m: ",
	[LLOG_WARN] =  "\x1b[35mWARN\x1b[0m:  ",
	[LLOG_INFO] =  "\x1b[34mINFO\x1b[0m:  ",
	[LLOG_DEBUG] = "DEBUG: ",
	[LLOG_DEBUG_VERBOSE] = "DEBVE: "
};

const int prios[] = {
	[LLOG_ERROR] = LOG_ERR,
	[LLOG_WARN] = LOG_WARNING,
	[LLOG_INFO] = LOG_INFO,
	[LLOG_DEBUG] = LOG_DEBUG
};

void ulog_internal(enum log_level log_level, const char *format, va_list *args) {
	(void) log_level; // Currently ignored
	fputs(names[log_level], stderr);
	if (log_level < LLOG_DEBUG_VERBOSE) {
		va_list copy;
		va_copy(copy, *args);
		vsyslog(prios[log_level], format, copy);
		va_end(copy);
	}
	vfprintf(stderr, format, *args);
}

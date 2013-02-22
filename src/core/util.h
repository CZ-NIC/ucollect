#ifndef UCOLLECT_UTIL_H
#define UCOLLECT_UTIL_H

#include <stdarg.h>

void die(const char *format, ...) __attribute__((format(printf, 1, 2))) __attribute__((noreturn));

#ifndef MAX_LOG_LEVEL
#define MAX_LOG_LEVEL LOG_DEBUG
#endif

enum log_level {
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_DEBUG_VERBOSE
};

void ulog_internal(enum log_level log_level, const char *format, va_list *args);

static inline void ulog(enum log_level log_level, const char *format, ...) __attribute__((format(printf, 2, 3)));
static inline void ulog(enum log_level log_level, const char *format, ...) {
	if (log_level > MAX_LOG_LEVEL)
		return;
	va_list args;
	va_start(args, format);
	ulog_internal(log_level, format, &args);
	va_end(args);
}

#endif

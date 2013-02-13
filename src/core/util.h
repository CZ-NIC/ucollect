#ifndef UCOLLECT_UTIL_H
#define UCOLLECT_UTIL_H

void die(const char *format, ...) __attribute__((format(printf, 1, 2))) __attribute__((noreturn));

enum log_level {
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_DEBUG_VERBOSE
};

void ulog(enum log_level log_level, const char *format, ...) __attribute__((format(printf, 2, 3)));

#endif

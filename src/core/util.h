/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef UCOLLECT_UTIL_H
#define UCOLLECT_UTIL_H

#include <stdarg.h>

void die(const char *format, ...) __attribute__((format(printf, 1, 2))) __attribute__((noreturn));

#ifndef MAX_LOG_LEVEL
#define MAX_LOG_LEVEL LLOG_DEBUG
#endif

enum log_level {
	LLOG_DIE,
	LLOG_ERROR,
	LLOG_WARN,
	LLOG_INFO,
	LLOG_DEBUG,
	LLOG_DEBUG_VERBOSE
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

void sanity_internal(const char *file, unsigned line, const char *check, const char *format, ...) __attribute__((format(printf, 4, 5))) __attribute__((noreturn));

// An assert-like function, but with printf message that can be added. It is not omitted from compilation like assert may be. Use for checking input parameters, for example. Logs on the ERROR level and aborts, effectively killing a plugin that failed the check.
#define sanity(check, ...) do { if (!(check)) sanity_internal(__FILE__, __LINE__, #check, __VA_ARGS__); } while (0)

#endif

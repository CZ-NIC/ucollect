/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC

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
	openlog("ucollect", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
	vsyslog(LOG_MAKEPRI(LOG_DAEMON, LOG_CRIT), format, copy);
	closelog(); // Close every time. Otherwise, it still logs to the old one after log rotation :-(
	va_end(copy);
	va_end(args);
	abort();
}

static const char *names[] = {
	[LLOG_ERROR] = "\x1b[31mERROR\x1b[0m: ",
	[LLOG_WARN] =  "\x1b[35mWARN\x1b[0m:  ",
	[LLOG_INFO] =  "\x1b[34mINFO\x1b[0m:  ",
	[LLOG_DEBUG] = "DEBUG: ",
	[LLOG_DEBUG_VERBOSE] = "DEBVE: "
};

static const int prios[] = {
	[LLOG_ERROR] = LOG_ERR,
	[LLOG_WARN] = LOG_WARNING,
	[LLOG_INFO] = LOG_INFO,
	[LLOG_DEBUG] = LOG_DEBUG
};

void ulog_internal(enum log_level log_level, const char *format, va_list *args) {
	(void) log_level; // Currently ignored
	if (log_level < LLOG_DEBUG_VERBOSE) {
		va_list copy;
		va_copy(copy, *args);
		vsyslog(prios[log_level], format, copy);
		va_end(copy);
	}
	fputs(names[log_level], stderr);
	vfprintf(stderr, format, *args);
}

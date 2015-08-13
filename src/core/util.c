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

#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <alloca.h>

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
	// Make sure die means really die, no signal handler for this now.
	// No checking the sigaction here. We would have no way to handle that
	// anyway.
	sigaction(SIGABRT, &(struct sigaction) {
		.sa_handler = SIG_DFL
	}, NULL);
	abort();
	// Last resort
	kill(getpid(), SIGKILL);
}

static const char *names[] = {
	[LLOG_DIE] = "\x1b[31;1mDIE\x1b[0m: ",
	[LLOG_ERROR] = "\x1b[31mERROR\x1b[0m: ",
	[LLOG_WARN] =  "\x1b[35mWARN\x1b[0m:  ",
	[LLOG_INFO] =  "\x1b[34mINFO\x1b[0m:  ",
	[LLOG_DEBUG] = "DEBUG: ",
	[LLOG_DEBUG_VERBOSE] = "DEBVE: "
};

static const int prios[] = {
	[LLOG_DIE] = LOG_CRIT,
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

void sanity_internal(const char *file, unsigned line, const char *check, const char *format, ...) {
	va_list args;
	va_start(args, format);
	va_list copy;
	va_copy(copy, args);
	size_t needed = vsnprintf(NULL, 0, format, args);
	char *output = alloca(needed + 1);
	vsnprintf(output, needed + 1, format, copy);
	va_end(args);
	va_end(copy);
	ulog(LLOG_ERROR, "%s:%u: Failed check '%s': %s", file, line, check, output);
	abort();
}

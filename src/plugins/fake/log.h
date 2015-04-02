/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#ifndef UCOLLECT_FAKE_LOG_H
#define UCOLLECT_FAKE_LOG_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

struct mem_pool;
struct context;
struct log;

enum event_type {
	EVENT_CONNECT, // A client connected
	EVENT_DISCONNECT, // A client disconnected/was disconnected gracefully
	EVENT_LOST, // A connection lost due to an error (either protocol, or network one)
	EVENT_CONNECT_EXTRA, // A client tried to connect, but we have too many open ones
	EVENT_TIMEOUT, // A client haven't sent anything for a long time
	EVENT_LOGIN // A client tried to log in
};

enum event_info_type {
	EI_NAME, // The login name
	EI_PASSWORD, // The password
	EI_ERROR, // The error
	EI_LAST // This is the last info bundled to the event
};

/*
 * Some info bundled with an event. The info is passed as an array of
 * these structures, last one being EI_LAST. Or, alternatively, a NULL
 * may be passed, in which case there is no additional info.
 */
struct event_info {
	enum event_info_type type;
	const char *content;
};

/*
 * Allocate new log structure. The permanent pool is for parts that'll live for
 * the whole time of the plugin ‒ the top level parts of the structure. The log
 * pool is reset on each dump, and holds the logged events.
 */
struct log *log_alloc(struct mem_pool *permanent_pool, struct mem_pool *log_pool) __attribute__((malloc)) __attribute__((nonnull)) __attribute__((returns_nonnull));
/*
 * Add another event into the log, with the current time.
 *
 * The return value indicates if the log should be sent to the server.
 */
bool log_event(struct context *context, struct log *log, char server_code, const uint8_t *address, size_t addr_len, enum event_type event, struct event_info *info) __attribute__((nonnull(1, 2, 4)));
/*
 * Dump the log into a binary format suitable for transmission over network.
 * The result is allocated from the temp pool of the given context and the
 * size is stored in the corresponding parameter. It is already prefixed by
 * a 'L' opcode.
 *
 * All the events from the log are cleared.
 */
uint8_t *log_dump(struct context *context, struct log *log, size_t *size) __attribute__((nonnull)) __attribute__((malloc)) __attribute__((returns_nonnull));

#endif

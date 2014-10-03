/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/trie.h"
#include "../../core/util.h"
#include "../../core/packet.h"

#include <string.h>
#include <assert.h>

struct user_data {
	bool active;
	struct mem_pool *active_pool, *standby_pool; // One pool to allocate the trie from, another to be able to copy some data to when cleaning the first one
	struct trie *connections; // We store the connections here
	size_t undecided, finished; // Number of yet undecided connections and number of decided ones
	size_t send_size_v4, send_size_v6; // How many records would be sent
	struct trie_data *timeout_head, *timeout_tail; // Link list sorted by the timeouts
	uint64_t timeout; // How long before a packet is timed out
};

enum event_type {
	EVENT_SYN, // SYN packet
	EVENT_ACK, // SYN+ACK packet
	EVENT_NAK, // Some kind of ICMP unreachable or such
	EVENT_TIMEOUT, // Timed out
	EVENT_MAX // A bumper
};

struct trie_data {
	uint64_t time; // Time of the first access (first packet seen)
	bool completed; // The thing has decided which kind it is.
	bool events[EVENT_MAX];
	bool v6;
	struct trie_data *next, *prev; // Link list sorted by timeouts
};

#define LIST_NODE struct trie_data
#define LIST_BASE struct user_data
#define LIST_HEAD timeout_head
#define LIST_TAIL timeout_tail
#define LIST_PREV prev
#define LIST_NAME(X) timeout_##X
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_REMOVE
#include "../../core/link_list.h"

static void init(struct context *context) {
	struct user_data *u = context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *u);
	*u = (struct user_data) {
		.active = true, // TODO: Load configuration from the server
		.active_pool = loop_pool_create(context->loop, context, "Refuse pool 1"),
		.standby_pool = loop_pool_create(context->loop, context, "Refuse pool 2"),
		.timeout = 30000
	};
	u->connections = trie_alloc(u->active_pool);
}

static void handle_event_found(struct context *context, enum event_type type, struct trie_data *d) {
	assert(d);
	struct user_data *u = context->user_data;
	d->events[type] = true;
	// Check if the thing should be decided
	if (d->events[EVENT_TIMEOUT] || (d->events[EVENT_SYN] && (d->events[EVENT_ACK] || d->events[EVENT_NAK]))) {
		if (d->events[EVENT_SYN] && !d->events[EVENT_ACK]) { // Started but was not accepted - report
			if (d->v6)
				u->send_size_v6 ++;
			else
				u->send_size_v4 ++;
		}
		u->undecided --;
		u->finished ++;
		timeout_remove(u, d);
	}
}

static void handle_event(struct context *context, enum event_type type, bool v6, const uint8_t *addr, uint16_t loc_port, uint16_t rem_port) {
	struct user_data *u = context->user_data;
	// Prepare the key
	size_t addr_len = v6 ? 16 : 4;
	size_t key_len = addr_len + sizeof loc_port + sizeof rem_port;
	uint8_t *key = mem_pool_alloc(context->temp_pool, key_len);
	memcpy(key, addr, addr_len);
	memcpy(key + addr_len, &loc_port, sizeof loc_port);
	memcpy(key + addr_len + sizeof loc_port, &rem_port, sizeof rem_port);
	// Look if the item exists there
	struct trie_data **node = trie_index(u->connections, key, key_len);
	if (!*node) { // First access to that thing, create it
		assert(type != EVENT_TIMEOUT); // Only existing items may time out
		struct trie_data *d = *node = timeout_append_pool(u, u->active_pool);
		d->time = loop_now(context->loop);
		d->completed = false;
		d->v6 = v6;
		memset(d->events, 0, sizeof d->events);
	}
	struct trie_data *d = *node;
	if (d->completed) {
		ulog(LLOG_DEBUG, "Seen event on decided packet %u->(%s):%u\n", (unsigned)loc_port, mem_pool_hex(context->temp_pool, addr, addr_len), (unsigned)rem_port);
		return;
	}
	handle_event_found(context, type, d);
}

// Timeout all the events that are too old and not yet decided
static void timeouts_evaluate(struct context *context) {
	uint64_t now = loop_now(context->loop);
	struct user_data *u = context->user_data;
	while (u->timeout_head && u->timeout_head->time + u->timeout < now) {
		struct trie_data *d = u->timeout_head;
		handle_event_found(context, EVENT_TIMEOUT, d);
		assert(d != u->timeout_head);
	}
}

static void packet(struct context *context, const struct packet_info *info) {
	if (!context->user_data->active)
		return; // Not yet activated, no config
	while (info->next) // Find the intermost packet
		info = info->next;
	if (info->layer != 'I')
		return;
	if (info->ip_protocol != 4 && info->ip_protocol != 6)
		return;
	if (info->app_protocol == 'T') { // A TCP packet. We are very interested in some of them.
		if (info->direction == DIR_OUT && (info->tcp_flags & TCP_SYN) && !(info->tcp_flags & TCP_ACK))
			// Outbound initial SYN packet ‒ initialization of the connection
			handle_event(context, EVENT_SYN, info->ip_protocol == 6, info->addresses[END_DST], info->ports[END_SRC], info->ports[END_DST]);
		if (info->direction == DIR_IN && (info->tcp_flags & TCP_SYN) && (info->tcp_flags & TCP_ACK))
			// The server accepts the connection
			handle_event(context, EVENT_ACK, info->ip_protocol == 6, info->addresses[END_SRC], info->ports[END_DST], info->ports[END_SRC]);
		if (info->direction == DIR_IN && (info->tcp_flags & TCP_RESET))
			// This could be NAK. Or it can be termination, but then, the SYN+ACK must have come before and this one would get ignored
			handle_event(context, EVENT_NAK, info->ip_protocol == 6, info->addresses[END_SRC], info->ports[END_DST], info->ports[END_SRC]);
		// Other TCP packets are somewhere in the middle of the stream and are not interesting at all
	}
	if (info->app_protocol == 'i' || info->app_protocol == 'I') {
		// TODO: Examine ICMP packets and find all the destination unreachable messages
	}
	timeouts_evaluate(context);
}

#ifdef STATIC
struct plugin *plugin_info_refused(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Refused",
		.init_callback = init,
		.packet_callback = packet,
		.version = 1
	};
	return &plugin;
}

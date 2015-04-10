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

#include "icmp.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/trie.h"
#include "../../core/util.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"

#include <string.h>
#include <assert.h>
#include <endian.h>
#include <arpa/inet.h>

struct user_data {
	bool active;
	struct mem_pool *active_pool, *standby_pool; // One pool to allocate the trie from, another to be able to copy some data to when cleaning the first one
	struct trie *connections; // We store the connections here
	size_t undecided, finished; // Number of yet undecided connections and number of decided ones
	size_t send_v4, send_v6; // How many records would be sent
	struct trie_data *timeout_head, *timeout_tail; // Link list sorted by the timeouts
	uint64_t timeout; // How long before a packet is timed out
	uint64_t max_age; // When to send data and consolidate
	uint32_t finished_limit, send_limit, undecided_limit;
	bool timeout_scheduled;
	size_t timeout_id;
	uint32_t config_version;
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
	bool events[EVENT_MAX];
	bool v6;
	bool completed; // The thing has decided which kind it is.
	bool transmitted;
	char nak_type;
	struct trie_data *next, *prev; // Link list sorted by timeouts
	struct trie_data *new_instance; // A friend allocated from new pool
};

#define LIST_NODE struct trie_data
#define LIST_BASE struct user_data
#define LIST_HEAD timeout_head
#define LIST_TAIL timeout_tail
#define LIST_PREV prev
#define LIST_NAME(X) timeout_##X
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_REMOVE
#define LIST_WANT_LFOR
#define LIST_INSERT_AFTER
#include "../../core/link_list.h"

static void transmit(struct context *context);
static void consolidate(struct context *context);

static void send_timeout(struct context *context, void *data, size_t id) {
	(void)data;
	(void)id;
	struct user_data *u = context->user_data;
	if (!u->send_v4 && !u->send_v6) {
		ulog(LLOG_DEBUG, "Refused connections timed out, but none to send\n");
		u->timeout_id = loop_timeout_add(context->loop, u->max_age, context, NULL, send_timeout);
		return;
	}
	ulog(LLOG_DEBUG, "Sending refused data because of timeout\n");
	u->timeout_scheduled = false;
	transmit(context);
	consolidate(context);
}

static void connected(struct context *context) {
	// Ask for configuration
	uplink_plugin_send_message(context, "C", 1);
}

static void init(struct context *context) {
	struct user_data *u = context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *u);
	*u = (struct user_data) {
		.active = false,
		.active_pool = loop_pool_create(context->loop, context, "Refuse pool 1"),
		.standby_pool = loop_pool_create(context->loop, context, "Refuse pool 2"),
		.timeout = 30000
	};
	u->connections = trie_alloc(u->active_pool);
	/*
	 * Try asking for the config right away. This may be needed in case
	 * we were reloaded (due to a crash of the plugin, for example) and
	 * we are already connected ‒ in such case, the connected would never
	 * be called.
	 *
	 * On the other hand, if we are not connected, the message will just
	 * get blackholed, so there's no problem with that either.
	 */
	connected(context);
}

struct conn_record {
	uint64_t time;
	char reason;
	uint8_t family;
	uint16_t loc_port;
	uint16_t rem_port;
	uint8_t address[];
} __attribute__((packed));

struct serialize_params {
	uint8_t *msg;
	size_t size;
};

static void serialize_callback(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	if (!data->completed)
		return; // Not completed yet, so don't send it.
	if (data->transmitted)
		return; // Leftover in data from sometime before.
	if (!data->events[EVENT_SYN] || data->events[EVENT_ACK]) {
		/*
		 * These are either incomplete scraps or successfull connection attempts.
		 * We don't send these. But we mark them as sent so they are removed on
		 * the next consolidation.
		 */
		data->transmitted = true;
		return;
	}
	// OK, the connection passed all criteria, really serialize it to the message.
	struct serialize_params *params = userdata;
	struct conn_record *record = (struct conn_record *)params->msg;
	size_t addr_len = data->v6 ? 16 : 4;
	assert(key_size == addr_len + 4);
	size_t serialized_len = sizeof(struct conn_record) + addr_len;
	assert(serialized_len <= params->size);
	uint16_t loc_port, rem_port;
	memcpy(&loc_port, key + addr_len, sizeof loc_port);
	memcpy(&rem_port, key + addr_len + sizeof rem_port, sizeof rem_port);
	*record = (struct conn_record) {
		.time = htobe64(data->time),
		.reason = data->events[EVENT_NAK] ? data->nak_type : 'T',
		.family = data->v6 ? 6 : 4,
		.loc_port = htons(loc_port),
		.rem_port = htons(rem_port)
	};
	memcpy(record->address, key, addr_len);
	data->transmitted = true;
	params->msg += serialized_len;
	params->size -= serialized_len;
}

static void transmit(struct context *context) {
	struct user_data *u = context->user_data;
	ulog(LLOG_INFO, "Sending %zu IPv4 refused connections and %zu IPv6 ones\n", u->send_v4, u->send_v6);
	size_t msg_size = 1 + sizeof(uint64_t) + u->send_v4 * (sizeof(struct conn_record) + 4) + u->send_v6 * (sizeof(struct conn_record) + 16);
	uint8_t *msg = mem_pool_alloc(context->temp_pool, msg_size);
	*msg = (uint8_t)'D';
	uint64_t now = htobe64(loop_now(context->loop));
	memcpy(msg + 1, &now, sizeof now);
	size_t start_offset = 1 + sizeof now;
	struct serialize_params params = {
		.msg = msg + start_offset,
		.size = msg_size - start_offset
	};
	trie_walk(u->connections, serialize_callback, &params, context->temp_pool);
	assert(params.size == 0);
	uplink_plugin_send_message(context, msg, msg_size);
	// Reset the counters to send data
	u->send_v4 = 0;
	u->send_v6 = 0;
	if (u->timeout_scheduled)
		loop_timeout_cancel(context->loop, u->timeout_id);
	u->timeout_scheduled = true;
	u->timeout_id = loop_timeout_add(context->loop, u->max_age, context, NULL, send_timeout);
}

struct consolidate_params {
	struct trie *dest;
	struct mem_pool *pool, *tmp;
	size_t undecided, finished, send_v4, send_v6;
};

static void consolidate_callback(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	if (data->transmitted)
		// Drop this one, we already sent it
		return;
	if (data->completed && data->events[EVENT_ACK])
		// This one is not going to be sent. Ever.
		return;
	if (data->completed && !data->events[EVENT_SYN])
		// There was no attempt
		return;
	// Create a copy of the node and put it into the other trie
	struct consolidate_params *params = userdata;
	struct trie_data *new = mem_pool_alloc(params->pool, sizeof *new);
	memcpy(new, data, sizeof *new);
	*trie_index(params->dest, key, key_size) = new;
	// Link to the new one, so it can be found in the linked list
	data->new_instance = new;
	// Update stats
	if (data->completed) {
		params->finished ++;
		if (data->v6)
			params->send_v6 ++;
		else
			params->send_v4 ++;
	} else {
		params->undecided ++;
	}
}

// Go through the trie of connections and copy the ones that are still useful to a new one, dropping the old
static void consolidate(struct context *context) {
	ulog(LLOG_DEBUG, "Consolidating refused connection store\n");
	struct user_data *u = context->user_data;
	struct consolidate_params params = {
		.dest = trie_alloc(u->standby_pool),
		.pool = u->standby_pool,
		.tmp = context->temp_pool
	};
	// Copy relevant nodes
	trie_walk(u->connections, consolidate_callback, &params, context->temp_pool);
	// Create a new linked list for timeouts
	struct user_data tmp_data = { .timeout_head = NULL };
	LFOR(timeout, old, u)
		timeout_insert_after(&tmp_data, old->new_instance, tmp_data.timeout_tail);
	u->timeout_head = tmp_data.timeout_head;
	u->timeout_tail = tmp_data.timeout_tail;
	// Drop the old data
	mem_pool_reset(u->active_pool);
	// Use the new values
	u->standby_pool = u->active_pool;
	u->active_pool = params.pool;
	u->connections = params.dest;
	assert(u->undecided == params.undecided);
	// We may lose some finished here
	assert(u->finished >= params.finished);
	u->finished = params.finished;
	assert(u->send_v4 == params.send_v4);
	assert(u->send_v6 == params.send_v6);
}

static void handle_event_found(struct context *context, enum event_type type, char nak_type, struct trie_data *d) {
	ulog(LLOG_DEBUG_VERBOSE, "Connection event %d on %p\n", (int)type, (void*)d);
	assert(d);
	struct user_data *u = context->user_data;
	d->events[type] = true;
	if (type == EVENT_NAK)
		d->nak_type = nak_type;
	// Check if the thing should be decided
	if (d->events[EVENT_TIMEOUT] || (d->events[EVENT_SYN] && (d->events[EVENT_ACK] || d->events[EVENT_NAK]))) {
		if (d->events[EVENT_SYN] && !d->events[EVENT_ACK]) { // Started but was not accepted - report
			if (d->v6)
				u->send_v6 ++;
			else
				u->send_v4 ++;
		}
		u->undecided --;
		u->finished ++;
		timeout_remove(u, d);
		d->completed = true;
	}
}

static void handle_event(struct context *context, enum event_type type, char nak_type, bool v6, const uint8_t *addr, uint16_t loc_port, uint16_t rem_port) {
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
		if (u->undecided >= u->undecided_limit) {
			ulog(LLOG_ERROR, "Too many undecided connections, droping\n");
			return;
		}
		u->undecided ++;
		struct trie_data *d = *node = timeout_append_pool(u, u->active_pool);
		d->time = loop_now(context->loop);
		d->completed = false;
		d->transmitted = false;
		d->v6 = v6;
		memset(d->events, 0, sizeof d->events);
	}
	struct trie_data *d = *node;
	if (d->completed) {
		ulog(LLOG_DEBUG, "Seen event on decided packet %u->(%s):%u\n", (unsigned)loc_port, mem_pool_hex(context->temp_pool, addr, addr_len), (unsigned)rem_port);
		return;
	}
	handle_event_found(context, type, nak_type, d);
}

// Timeout all the events that are too old and not yet decided
static void timeouts_evaluate(struct context *context) {
	uint64_t now = loop_now(context->loop);
	struct user_data *u = context->user_data;
	while (u->timeout_head && u->timeout_head->time + u->timeout < now) {
		struct trie_data *d = u->timeout_head;
		handle_event_found(context, EVENT_TIMEOUT, 0, d);
		assert(d != u->timeout_head);
	}
}

static void limits_check(struct context *context) {
	struct user_data *u = context->user_data;
	if (u->send_limit <= u->send_v4 + u->send_v6) {
		// Too many things to send
		transmit(context);
		consolidate(context);
	} else if (u->finished_limit <= u->finished) {
		// Not enough to send, but there are still many finished things in the memory, so drop some
		consolidate(context);
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
			handle_event(context, EVENT_SYN, 0, info->ip_protocol == 6, info->addresses[END_DST], info->ports[END_SRC], info->ports[END_DST]);
		if (info->direction == DIR_IN && (info->tcp_flags & TCP_SYN) && (info->tcp_flags & TCP_ACK))
			// The server accepts the connection
			handle_event(context, EVENT_ACK, 0, info->ip_protocol == 6, info->addresses[END_SRC], info->ports[END_DST], info->ports[END_SRC]);
		if (info->direction == DIR_IN && (info->tcp_flags & TCP_RESET))
			// This could be NAK. Or it can be termination, but then, the SYN+ACK must have come before and this one would get ignored
			handle_event(context, EVENT_NAK, 'P', info->ip_protocol == 6, info->addresses[END_SRC], info->ports[END_DST], info->ports[END_SRC]);
		// Other TCP packets are somewhere in the middle of the stream and are not interesting at all
	}
	if ((info->app_protocol == 'i' || info->app_protocol == 'I') && info->direction == DIR_IN) {
		size_t addr_len;
		const uint8_t *addr;
		uint16_t loc_port, rem_port;
		char nak_type = nak_parse(info, &addr_len, &addr, &loc_port, &rem_port);
		if (nak_type)
			handle_event(context, EVENT_NAK, nak_type, info->ip_protocol == 6, addr, loc_port, rem_port);
	}
	timeouts_evaluate(context);
	limits_check(context);
}

struct config_packet {
	uint32_t version;
	uint32_t finished_limit;
	uint32_t send_limit;
	uint32_t undecided_limit;
	uint64_t timeout;
	uint64_t max_age;
} __attribute__((packed));

static void uplink_data(struct context *context, const uint8_t *data, size_t length) {
	if (!length) {
		ulog(LLOG_ERROR, "Empty message for the Refused plugin\n");
		abort();
	}
	switch (*data) {
		case 'C': {
			const struct config_packet *packet = (const struct config_packet *)(data + 1);
			if (length - 1 < sizeof *packet) {
				ulog(LLOG_ERROR, "Config data too short for Refused plugin, need %zu, have only %zu\n", sizeof *packet, length - 1);
				abort();
			}
			if (length - 1 > sizeof *packet)
				ulog(LLOG_ERROR, "Too much data for Refused config, need only %zu, have %zu (ignorig for forward compatibility)\n", sizeof *packet, length - 1);
			struct user_data *u = context->user_data;
			if (u->config_version == ntohl(packet->version)) {
				ulog(LLOG_INFO, "Refused config version not changed from %u\n", (unsigned)u->config_version);
				return;
			}
			u->config_version = ntohl(packet->version);
			u->finished_limit = ntohl(packet->finished_limit);
			u->send_limit = ntohl(packet->send_limit);
			u->undecided_limit = ntohl(packet->undecided_limit);
			u->timeout = be64toh(packet->timeout);
			u->max_age = be64toh(packet->max_age);
			ulog(LLOG_INFO, "Received Refused config version %u\n", (unsigned)u->config_version);
			if (u->timeout_scheduled)
				loop_timeout_cancel(context->loop, u->timeout_id);
			u->active = true;
			u->timeout_id = loop_timeout_add(context->loop, u->max_age, context, NULL, send_timeout);
			u->timeout_scheduled = true;
			break;
		}
		default:
			ulog(LLOG_ERROR, "Invalid opcode for Refused plugin (ignoring for forward compatibility): %c\n", (char)*data);
			return;
	}
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
		.uplink_connected_callback = connected,
		.uplink_data_callback = uplink_data,
		.version = 1
	};
	return &plugin;
}

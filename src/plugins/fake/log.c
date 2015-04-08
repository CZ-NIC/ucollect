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

#include "log.h"

#include "../../core/mem_pool.h"
#include "../../core/trie.h"
#include "../../core/context.h"
#include "../../core/loop.h"
#include "../../core/uplink.h"
#include "../../core/util.h"

#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

/*
 * Single event in the log.
 */
struct log_event {
	struct log_event *next;		// For linked list managment
	char code;		// The server name/code that generated the event
	const uint8_t *addr;		// Which address was the remote
	uint64_t timestamp;		// When it happened
	uint8_t addr_len;
	enum event_type type;
	uint8_t info_count;		// Some extra info about the event
	struct event_info extra_info[];
};

/*
 * The log consists of two main items.
 * • Sequential log of the events, in a linked list. This is eventually dumped to
 *   the server.
 * • A trie with login IDs (server name+remote IP address), each holding number of
 *   login attempts on that ID. This is to check if anythig exceeds the limit.
 *   TODO: Ability to ignore some in that limit, so we don't send too often. Maybe
 *   trigerred for some time after first dump caused by this? Or updated from server?
 *
 * Then there's some metadata.
 */
struct log {
	struct mem_pool *pool;
	struct log_event *head, *tail;
	struct trie *limit_trie;
	size_t expected_serialized_size; // How large the result will be when we dump it.
	size_t ip_limit, size_limit;     // Limits on when to send.
	bool log_credentials;		 // Should we send the login name and password?
};

struct trie_data {
	unsigned attempt_count;
};

#define LIST_NODE struct log_event
#define LIST_BASE struct log
#define LIST_NAME(X) log_##X
#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_LFOR
#include "../../core/link_list.h"

static void log_clean(struct log *log) {
	mem_pool_reset(log->pool);
	log->head = log->tail = NULL;
	log->expected_serialized_size = 0;
	log->limit_trie = trie_alloc(log->pool);
}

struct log *log_alloc(struct mem_pool *permanent_pool, struct mem_pool *log_pool) {
	struct log *result = mem_pool_alloc(permanent_pool, sizeof *result);
	*result = (struct log) {
		.pool = log_pool,
		// TODO: Just arbitrarily chosen. Allow to be configured.
		.ip_limit = 5,
		.size_limit = 4096 * 1024
	};
	log_clean(result);
	return result;
}

enum addr_type {
	AT_IPv4,
	AT_IPv6
};

struct event_header {
	uint32_t timestamp;		// How many milliseconds ago it happened. uint32_t is enough, as it is more than 49 days.
	enum event_type type:8;
	enum addr_type addr:8;
	uint8_t info_count;
	char code;
} __attribute__((packed));

// The IPv6 mapped IPv4 addresses are 0000:0000:FFFF:<IP>.
static const uint8_t mapped_prefix[] = { [8] = 0xFF, [9] = 0xFF, [10] = 0xFF, [11] = 0xFF };

bool log_event(struct context *context, struct log *log, char server_code, const uint8_t *address, size_t addr_len, enum event_type type, struct event_info *info) {
	// If it's IPv6 mapped IPv4, store it as IPv4 only
	if (memcmp(address, mapped_prefix, sizeof mapped_prefix) == 0) {
		addr_len -= sizeof mapped_prefix;
		address += sizeof mapped_prefix;
	}
	size_t info_count = 0;
	size_t expected_size = sizeof(struct event_header);
	expected_size += addr_len;
	if (info)
		for (struct event_info *i = info; i->type != EI_LAST; i ++)
			if (log->log_credentials || (i->type != EI_NAME && i->type != EI_PASSWORD))
					info_count ++;
	struct log_event *event = mem_pool_alloc(log->pool, sizeof *event + info_count * sizeof event->extra_info[0]);
	uint8_t *addr_cp = mem_pool_alloc(log->pool, addr_len);
	memcpy(addr_cp, address, addr_len);
	*event = (struct log_event) {
		.code = server_code,
		.addr = addr_cp,
		.addr_len = addr_len,
		.timestamp = loop_now(context->loop),
		.type = type,
		.info_count = info_count
	};
	for (size_t i = 0; i < info_count; i ++) {
		if (!log->log_credentials && (info[i].type == EI_NAME || info[i].type == EI_PASSWORD))
			// Skip the login credentials if we shouldn't log them
			continue;
		event->extra_info[i] = (struct event_info) {
			.type = info[i].type,
			.content = mem_pool_strdup(log->pool, info[i].content)
		};
		expected_size += 5 + strlen(info[i].content); // +4 for length, +1 for the info flags/type.
	}
	log_insert_after(log, event, log->tail);
	log->expected_serialized_size += expected_size;
	unsigned attempt_count = 0;
	if (type == EVENT_LOGIN) {
		size_t id_len = 1 + addr_len;
		uint8_t login_id[id_len];
		*login_id = server_code;
		memcpy(login_id + 1, address, addr_len);
		struct trie_data **data = trie_index(log->limit_trie, login_id, id_len);
		if (!*data) {
			*data = mem_pool_alloc(log->pool, sizeof **data);
			attempt_count = (*data)->attempt_count = 1;
		} else {
			attempt_count = ++ (*data)->attempt_count;
		}
	}
	return attempt_count >= log->ip_limit || log->expected_serialized_size >= log->size_limit;
}

uint8_t *log_dump(struct context *context, struct log *log, size_t *size) {
	if (!log->expected_serialized_size) {
		*size = 0;
		return NULL;
	}
	uint64_t now = loop_now(context->loop);
	uint64_t limit = 0x100000000;
	*size = log->expected_serialized_size + 1;
	uint8_t *result = mem_pool_alloc(context->temp_pool, log->expected_serialized_size + 1), *pos = result + 1;
	size_t rest = *size - 1;
	*result = 'L';
	LFOR(log, event, log) {
		assert(event->timestamp + limit > now);
		assert(event->addr_len == 4 || event->addr_len == 16);
		assert(event->info_count < 16);
		struct event_header header = {
			.timestamp = htonl(now - event->timestamp),
			.type = event->type,
			.addr = event->addr_len == 4 ? AT_IPv4 : AT_IPv6,
			.info_count = event->info_count,
			.code = event->code
		};
		assert(rest >= event->addr_len + sizeof header);
		memcpy(pos, &header, sizeof header);
		pos += sizeof header;
		memcpy(pos, event->addr, event->addr_len);
		pos += event->addr_len;
		rest -= event->addr_len + sizeof header;
		for (size_t i = 0; i < event->info_count; i ++) {
			assert(rest > 0);
			assert(event->extra_info[i].type != EI_LAST);
			*pos ++ = event->extra_info[i].type;
			rest --;
			uplink_render_string(event->extra_info[i].content, strlen(event->extra_info[i].content), &pos, &rest);
		}
	}
	assert(pos == result + *size);
	assert(rest == 0);
	log_clean(log);
	return result;
}

void log_set_send_credentials(struct log *log, bool send) {
	ulog(LLOG_INFO, "Sending login credentials %s\n", send ? "enabled" : "disabled");
	log->log_credentials = send;
}

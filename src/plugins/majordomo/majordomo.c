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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/loop.h"
#include "../../core/trie.h"

#define DUMP_FILE_DST "/tmp/ucollect_majordomo"
#define SOURCE_SIZE_LIMIT 6000
//in ms - 1 minute
#define DUMP_TIMEOUT 60000

// IPv6 has longer addresses and strings, use them - don't care about few bytes overhead
#define KEYS_ADDR_LEN 16
#define ADDRSTRLEN (INET6_ADDRSTRLEN + 1)

// Define constant SWAP_DIRECTION for usage in development environment (i.e. local interface on personal computer)
#ifdef SWAP_DIRECTION
#define DIRECTION_UPLOAD DIR_OUT
#define DIRECTION_DOWNLOAD DIR_IN
#else
#define DIRECTION_UPLOAD DIR_IN
#define DIRECTION_DOWNLOAD DIR_OUT
#endif

struct key {
	unsigned char from[KEYS_ADDR_LEN];
	unsigned char to[KEYS_ADDR_LEN];
	unsigned char from_addr_len;
	unsigned char to_addr_len;
	char protocol;
	uint16_t port;
};

struct trie_data {
	uint64_t u_count;
	uint64_t u_size;
	uint64_t u_data_size;
	uint64_t d_count;
	uint64_t d_size;
	uint64_t d_data_size;
};

struct src_key {
	unsigned char addr[KEYS_ADDR_LEN];
	unsigned char addr_len;
};

struct src_item {
	struct src_key from;
	struct trie_data other;
	size_t items_in_comm_list;
	struct src_item *next;
	struct src_item *prev;
};

struct src_items {
	struct src_item *head, *tail;
	size_t count;
};

#define LIST_NODE struct src_item
#define LIST_BASE struct src_items
#define LIST_NAME(X) src_items_##X
#define LIST_COUNT count
#define LIST_PREV prev
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#include "../../core/link_list.h"

struct filter_rule {
	struct in6_addr addr;
	size_t prefix;
	int family;
};

struct user_data {
	FILE *file;
	struct trie *communication;
	struct src_items sources;
	struct mem_pool *data_pool;
	struct mem_pool *config_pool;
	struct filter_rule *filter;
	size_t filter_size;
	size_t timeout;
	char *src_str;
	char *dst_str;
	FILE *dump_file;
};

static uint32_t masks[33];

static void precompute_masks() {
	uint32_t mask = 0xFFFFFFFF;

	for (ssize_t i = 32; i >= 0; i--) {
		masks[i] = htonl(mask);
		mask <<= 1;
	}
}

static bool bitcmp(uint32_t *a, uint32_t *b, size_t bits) {
	while (bits > 32) {
		if (a[0] != b[0]) return false;
		a++;
		b++;
		bits -= 32;
	}

	return ((a[0] & masks[bits]) == (b[0] & masks[bits]));
}

static bool parse_address(const char *addrstr, struct in6_addr *addr, int *family) {
	if (inet_pton(AF_INET, addrstr, addr) == 1) {
		*family = 4;
		return true;
	}
	if (inet_pton(AF_INET6, addrstr, addr) == 1) {
		*family = 6;
		return true;
	}

	return false;
}

static void get_string_from_raw_bytes(unsigned char *bytes, unsigned char addr_len, char output[ADDRSTRLEN]) {
	if (addr_len == 4) {
		struct in_addr addr;

		memcpy(&addr, bytes, addr_len);

		if (inet_ntop(AF_INET, (void *)&addr, output, INET_ADDRSTRLEN) == NULL) {
			//OK, any reason why it could fail?
			strcpy(output, "FAILED");
			ulog(LLOG_ERROR, "MAJORDOMO: conversion failed\n");
		}

	} else if (addr_len == 16) {
		struct in6_addr addr;

		memcpy(&addr, bytes, addr_len);

		if (inet_ntop(AF_INET6, (void *)&addr, output, ADDRSTRLEN) == NULL) {
			//OK, any reason why it could failed?
			strcpy(output, "FAILED");
			ulog(LLOG_ERROR, "MAJORDOMO: conversion failed\n");
		}
	} else if (addr_len == 6) {
		sprintf(output, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
	}
}

static void update_value(struct trie_data *value, enum direction direction, uint64_t size, uint64_t data_size) {
	if (direction == DIRECTION_UPLOAD) {
		value->u_count++;
		value->u_size += size;
		value->u_data_size += data_size;
	} else if (direction == DIRECTION_DOWNLOAD) {
		value->d_count++;
		value->d_size += size;
		value->d_data_size += data_size;
	} else {
		// DIR_UNKNOWN is filtered in packet_handle
		assert(0);
	}
}

static struct key* build_key(struct mem_pool *pool,
	const unsigned char *from, unsigned char from_addr_len,
	const unsigned char *to, unsigned char to_addr_len,
	char protocol, uint64_t port
	) {

	struct key *key = mem_pool_alloc(pool, sizeof *key);
	memset(key, 0, sizeof *key);
	memcpy(key->from, from, from_addr_len);
	memcpy(key->to, to, to_addr_len);
	key->from_addr_len = from_addr_len;
	key->to_addr_len = to_addr_len;
	key->protocol = protocol; key->port = port;

	return key;
}

static void init_trie_data(struct mem_pool *pool, struct trie_data **data, const struct packet_info *info) {
	*data = mem_pool_alloc(pool, sizeof **data);
	**data = (struct trie_data) {
		.u_count = 1,
		.u_size = info->length,
		.u_data_size = info->length - info->hdr_length
		// Item can be created only in one direction and the rest will be zero
	};
}

static struct src_item *find_src(struct src_items *sources, const unsigned char *from, unsigned char addr_len) {
	LFOR(src_items, it, sources) {
		if (it->from.addr_len == addr_len && memcmp(it->from.addr, from, addr_len) == 0) {
			return it;
		}
	}

	return NULL;
}

static bool filter_address(struct user_data *d, const void *addr_bytes, int family) {
	struct in6_addr addr;
	memcpy(&addr, addr_bytes, (family == 4 ? 4 : 16));

	for (size_t i = 0; i < d->filter_size; i++) {
		if (family == d->filter[i].family && bitcmp((uint32_t *) &addr, (uint32_t *) &(d->filter[i].addr), d->filter[i].prefix))
			return true;
	}

	return false;
}

void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *d = context->user_data;
	const struct packet_info *l2 = info;

	// Drop packets with UNKNOWN direction
	if (info->direction != DIRECTION_UPLOAD && info->direction != DIRECTION_DOWNLOAD) return;
	// Accept only ethernet at L2
	if (info->layer != 'E') return;
	// Go to IP packet if any
	if (l2->next == NULL) return;
	info = info->next;
	// Interested only in UDP and TCP packets (+ check IP Layer)
	if (info->layer != 'I') return;
	if (info->app_protocol != 'T' && info->app_protocol != 'U') return;
	// Interested only in INET and INET6
	if (info->ip_protocol != 4 && info->ip_protocol != 6) return;

	enum endpoint local_endpoint, remote_endpoint;
	if (l2->direction == DIRECTION_UPLOAD) {
		local_endpoint = END_SRC;
		remote_endpoint = END_DST;
	} else {
		local_endpoint = END_DST;
		remote_endpoint = END_SRC;
	}

	// Filter IP addresses according to configuration
	if (filter_address(d, info->addresses[remote_endpoint], info->ip_protocol)) return;

	// Do not handle packets with MAC address that starts with odd numbers (multi- or broadcasts)
	if ((((uint8_t *) l2->addresses[local_endpoint])[0] % 2) == 1 ||
		(((uint8_t *) l2->addresses[remote_endpoint])[0] % 2) == 1)
		return;

	// Check situation about this packet
	struct key *key = build_key(context->temp_pool,
			l2->addresses[local_endpoint], l2->addr_len,
			info->addresses[remote_endpoint], info->addr_len,
			info->app_protocol, info->ports[remote_endpoint]
	);

	struct trie_data **data = trie_index(d->communication, (uint8_t *) key, sizeof *key);

	// Item exists
	if (*data != NULL) {
		//Update info
		update_value(*data, l2->direction, info->length, (info->length - info->hdr_length));
		return;
	}

	// Item doesn't exists; check source's status
	struct src_item *src = find_src(&(d->sources), l2->addresses[local_endpoint], l2->addr_len);
	// This is first communication from this source
	if (src == NULL) {
		init_trie_data(d->data_pool, data, info);

		src = src_items_append_pool(&(d->sources), d->data_pool);
		memcpy(src->from.addr, l2->addresses[local_endpoint], l2->addr_len);
		src->from.addr_len = l2->addr_len;
		src->other = (struct trie_data) {
			.u_count = 0 // Init all with zero
		};
		src->items_in_comm_list = 1;

	} else {
		// Source has some records; check its limit
		if (src->items_in_comm_list < SOURCE_SIZE_LIMIT) {
			init_trie_data(d->data_pool, data, info);
		} else {
			// Source exceeded the limit - update its 'other' value
			update_value(&(src->other), l2->direction, info->length, (info->length - info->hdr_length));
		}
	}
}

static void dump_item(const uint8_t *key_bytes, size_t key_size, struct trie_data *data, void *userdata) {
	struct user_data *d = (struct user_data *) userdata;
	struct key *key = (struct key *) key_bytes;
	(void) key_size;

	get_string_from_raw_bytes(key->from, key->from_addr_len, d->src_str);
	get_string_from_raw_bytes(key->to, key->to_addr_len, d->dst_str);

	const char *app_protocol;
	if (key->protocol == 'T') {
		app_protocol = "TCP";
	} else if (key->protocol == 'U') {
		app_protocol = "UDP";
	} else {
		ulog(LLOG_ERROR, "Invalid majordomo protocol: %c\n", key->protocol);
		abort();
	}

	fprintf(d->dump_file,
		"%s,%s,%s,%" PRIu16 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
		app_protocol,
		d->src_str,
		d->dst_str,
		key->port,
		data->d_count,
		data->d_size,
		data->d_data_size,
		data->u_count,
		data->u_size,
		data->u_data_size
	);
}

static void dump(struct context *context) {
	struct user_data *d = context->user_data;
	d->dump_file = fopen(DUMP_FILE_DST, "a");
	if (d->dump_file == NULL) {
		ulog(LLOG_ERROR, "Can't open Majordomo dump file %s", DUMP_FILE_DST);
		//Nothing to do now
		return;
	}

	trie_walk(d->communication, dump_item, d, context->temp_pool);

	LFOR(src_items, it, &(d->sources)) {
		get_string_from_raw_bytes(it->from.addr, it->from.addr_len, d->src_str);
		fprintf(d->dump_file,
			"%s,%s,%s,%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
			"both",
			d->src_str,
			"other",
			"all",
			it->other.d_count,
			it->other.d_size,
			it->other.d_data_size,
			it->other.u_count,
			it->other.u_size,
			it->other.u_data_size
		);
	}

	//Cleanup
	//Drop dumped data
	mem_pool_reset(d->data_pool);
	//Reinit user_data items
	d->sources.head = NULL;
	d->sources.tail = NULL;
	d->sources.count = 0;
	d->communication = trie_alloc(d->data_pool);
	//Close dump file
	fclose(d->dump_file);
}

void scheduled_dump(struct context *context, void *data, size_t id) {
	(void) data;
	(void) id;
	dump(context);
	//Schedule next dump
	context->user_data->timeout = loop_timeout_add(context->loop, DUMP_TIMEOUT, context, NULL, scheduled_dump);
}

void init(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.data_pool = loop_pool_create(context->loop, context, "Majordomo data pool"),
		.config_pool = loop_pool_create(context->loop, context, "Majordomo config pool"),
		.timeout = loop_timeout_add(context->loop, DUMP_TIMEOUT, context, NULL, scheduled_dump),
		.sources = (struct src_items) {
			.count = 0
		},
		.src_str = mem_pool_alloc(context->permanent_pool, ADDRSTRLEN),
		.dst_str = mem_pool_alloc(context->permanent_pool, ADDRSTRLEN)
	};
	context->user_data->communication = trie_alloc(context->user_data->data_pool),

	precompute_masks();
}

static bool parse_option(struct mem_pool *temp_pool, const char *cfg_line, struct in6_addr *addr, size_t *prefix, int *family) {
	char *line = mem_pool_strdup(temp_pool, cfg_line);
	char *pos = strchr(line, '/');
	if (!pos)
		return false;
	pos[0] = '\0';
	pos++;

	if (!parse_address(line, addr, family))
		return false;

	*prefix = atoi(pos);
	if (*prefix <= 0 || *prefix > ((*family == 4) ? 32 : 128))
		return false;

	return true;
}

bool check_config(struct context *context) {
	struct in6_addr dummy_addr;
	size_t dummy_prefix;
	int dummy_family;

	const struct config_node *conf = loop_plugin_option_get(context, "ignore_subnet");
	if (!conf) {
		ulog(LLOG_WARN, "Majordomo: No subnet filter rules found!\n");
		return true;
	}

	for (size_t i = 0; i < conf->value_count; i++) {
		if (!parse_option(context->temp_pool, conf->values[i], &dummy_addr, &dummy_prefix, &dummy_family))
			return false;
	}

	return true;
}

void finish_config(struct context *context, bool commit) {
	struct user_data *d = context->user_data;

	// Do nothing on revert
	if (!commit)
		return;

	// Reset pool with old configuration
	mem_pool_reset(d->config_pool);
	// Empty filter is acceptable
	d->filter = NULL;
	d->filter_size = 0;

	const struct config_node *conf = loop_plugin_option_get(context, "ignore_subnet");
	if (!conf)
		return;
	d->filter_size = conf->value_count;
	d->filter = mem_pool_alloc(d->config_pool, d->filter_size * sizeof(*d->filter));

	// Parse (again) new configuration and store it
	for (size_t i = 0; i < d->filter_size; i++) {
		parse_option(context->temp_pool, conf->values[i], &(d->filter[i].addr), &(d->filter[i].prefix), &(d->filter[i].family));
		ulog(LLOG_DEBUG, "Majordomo: Add %s to subnet filter\n", conf->values[i]);
	}
}

void destroy(struct context *context) {
	dump(context);
}

#ifdef STATIC
struct plugin *plugin_info_majordomo(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Majordomo",
		.packet_callback = packet_handle,
		.init_callback = init,
		.finish_callback = destroy,
		.config_check_callback = check_config,
		.config_finish_callback = finish_config
	};
	return &plugin;
}

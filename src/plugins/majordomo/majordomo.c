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

/*
***************************** WARNING ****************************

This version of Majordomo plugin has no limitation for number of the source
devices. So, please, do not use this plugin in server rooms.

Limitation will appear in some next version, if will be necessary, or in
enterprise edition ;-)

*/
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <endian.h>
#include <stdio.h>
#include <inttypes.h>

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/loop.h"

#define DUMP_FILE_DST "/tmp/ucollect_majordomo"
#define SOURCE_SIZE_LIMIT 6000
//in ms - 1 minute
#define DUMP_TIMEOUT 60000

#define KEYS_ADDR_LEN 16

// Turris needs to define SWAP_DIRECTION
// This is temporary solution, we need to find out what's wrong
//#define SWAP_DIRECTION

#ifdef SWAP_DIRECTION
#define DIRECTION_UPLOAD DIR_IN
#define DIRECTION_DOWNLOAD DIR_OUT
#else
#define DIRECTION_UPLOAD DIR_OUT
#define DIRECTION_DOWNLOAD DIR_IN
#endif

struct key {
	unsigned char from[KEYS_ADDR_LEN];
	unsigned char to[KEYS_ADDR_LEN];
	unsigned char from_addr_len;
	unsigned char to_addr_len;
	char protocol;
	uint16_t port;
};

struct src_key {
	unsigned char addr[KEYS_ADDR_LEN];
	unsigned char addr_len;
};

struct value {
	uint64_t packets_count;
	uint64_t packets_size;
	uint64_t data_size;
};

struct comm_item {
	struct key key;
	struct value value;
	struct comm_item *next;
	struct comm_item *prev;
	struct src_item *src_parent;
};

struct comm_items {
	struct comm_item *head, *tail;
	size_t count;
};

struct src_item {
	struct src_key from;
	struct value other;
	size_t items_in_comm_list;
	struct src_item *next;
	struct src_item *prev;
};

struct src_items {
	struct src_item *head, *tail;
	size_t count;
};

#define LIST_NODE struct comm_item
#define LIST_BASE struct comm_items
#define LIST_NAME(X) items_##X
#define LIST_COUNT count
#define LIST_PREV prev
#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_REMOVE
#define LIST_WANT_LFOR
#include "../../core/link_list.h"


#define LIST_NODE struct src_item
#define LIST_BASE struct src_items
#define LIST_NAME(X) src_items_##X
#define LIST_COUNT count
#define LIST_PREV prev
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#include "../../core/link_list.h"

struct user_data {
	FILE *file;
	struct comm_items *communication;
	struct src_items *sources;
	struct mem_pool *list_pool;
	size_t timeout;
};

static void get_string_from_raw_bytes(unsigned char *bytes, unsigned char addr_len, char *output) {
	if (addr_len == 4) {
		struct in_addr addr;

		memcpy(&addr, bytes, addr_len);

		if (inet_ntop(AF_INET, (void *)&addr, output, INET_ADDRSTRLEN) == NULL) {
			//OK, any reason why it could failed?
			strcpy(output, "FAILED");
			ulog(LLOG_ERROR, "MAJORDOMO: conversion failed\n");
		}

	} else if (addr_len == 16) {
		struct in6_addr addr;

		memcpy(&addr, bytes, addr_len);

		if (inet_ntop(AF_INET6, (void *)&addr, output, INET6_ADDRSTRLEN) == NULL) {
			//OK, any reason why it could failed?
			strcpy(output, "FAILED");
			ulog(LLOG_ERROR, "MAJORDOMO: conversion failed\n");
		}
	} else if (addr_len == 6) {
		sprintf(output, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
	}
}

static bool key_equals(struct comm_item *item, const unsigned char *from, unsigned char from_addr_len, const unsigned char *to, unsigned char to_addr_len, char protocol, uint16_t port) {
	return (
			item->key.from_addr_len == from_addr_len &&
			item->key.to_addr_len == to_addr_len &&
			item->key.protocol == protocol &&
			item->key.port == port &&
			memcmp(item->key.from, from, from_addr_len) == 0 &&
			memcmp(item->key.to, to, to_addr_len) == 0
		);
}

static struct comm_item *find_item(struct comm_items *comm, const unsigned char *from, unsigned char from_addr_len, const unsigned char *to, unsigned char to_addr_len, unsigned char protocol, uint16_t port) {
	LFOR(items, it, comm) {
		if (key_equals(it, from, from_addr_len, to, to_addr_len, protocol, port)) {
			return it;
		}
	}

	return NULL;
}

static struct src_item *find_src(struct src_items *sources, const unsigned char *from, unsigned char addr_len) {
	LFOR(src_items, it, sources) {
		if (it->from.addr_len == addr_len && memcmp(it->from.addr, from, addr_len) == 0) {
			return it;
		}
	}

	return NULL;
}

static struct comm_item *create_comm_item(struct comm_items *communication, struct mem_pool *list_pool, const unsigned char *from, unsigned char from_addr_len, const unsigned char *to, unsigned char to_addr_len, const struct packet_info *info) {
	struct comm_item *item;
	//Create item
	item = mem_pool_alloc(list_pool, sizeof *item);
	items_insert_after(communication, item, NULL); //NULL == insert after head
	//Fill item's data
	memcpy(item->key.from, from, from_addr_len);
	memcpy(item->key.to, to, to_addr_len);
	item->key.protocol = info->app_protocol;
	item->key.port = info->ports[END_DST];
	item->key.from_addr_len = from_addr_len;
	item->key.to_addr_len = to_addr_len;
	item->value.packets_count = 1;
	item->value.packets_size = info->length;
	item->value.data_size = info->length - info->hdr_length;

	return item;
}

void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *d = context->user_data;

	// We are interested in outgoing packets only.
	if (info->direction != DIRECTION_UPLOAD) {
		//Only outgoing packets
		return;
	}

	if (info->layer != 'E') {
		ulog(LLOG_DEBUG_VERBOSE, "majordomo: first layers wasn't Ethernet.\n");
		return;
	}

	const unsigned char *src_mac = info->addresses[END_SRC];
	if (info->addr_len != 6) {
		ulog(LLOG_ERROR, "majordomo: Found packet on ethernet layer with bad address size\n");
		return;
	}
	unsigned char src_addr_len = info->addr_len;

	// Go to IP packet if any
	if (info->next == NULL) {
		return;
	}
	info = info->next;

	// Interested only in UDP and TCP packets (IP Layer)
	if (info->layer != 'I') {
		return;
	}
	if (info->app_protocol != 'T' && info->app_protocol != 'U') {
		return;
	}

	//Check situation about this packet
	struct comm_item *item = find_item(d->communication, src_mac, src_addr_len, (unsigned char *) info->addresses[END_DST], info->addr_len, info->app_protocol, info->ports[END_DST]);
	struct src_item *src = find_src(d->sources, src_mac, src_addr_len);

	//This item exists
	if (item != NULL) {
		//Update info
		item->value.packets_count++;
		item->value.packets_size += info->length;
		item->value.data_size += (info->length - info->hdr_length);
		//Update position
		items_remove(d->communication, item);
		items_insert_after(d->communication, item, NULL);

	//Item doesn't exists; check source status
	} else {
		//This is first communication from this source
		if (src == NULL) {
			item = create_comm_item(d->communication, d->list_pool, src_mac, src_addr_len, info->addresses[END_DST], info->addr_len, info);
			//Create source record
			src = src_items_append_pool(d->sources, d->list_pool);
			//Fill source data
			memcpy(src->from.addr, src_mac, src_addr_len);
			src->from.addr_len = src_addr_len;
			src->other.packets_count = 0;
			src->other.packets_size = 0;
			src->other.data_size = 0;
			src->items_in_comm_list = 1;
			//Add link into item
			item->src_parent = src;

		} else {
			//Source has some records; check its limit
			if (src->items_in_comm_list < SOURCE_SIZE_LIMIT) {
				item = create_comm_item(d->communication, d->list_pool, src_mac, src_addr_len, info->addresses[END_DST], info->addr_len, info);
				//Link item with its parent
				item->src_parent = src;
				item->src_parent->items_in_comm_list++;
			} else {
				//Source exceeded the limit - update its 'other' value
				src->other.packets_count++;
				src->other.packets_size += info->length;
				src->other.data_size += (info->length - info->hdr_length);
			}
		}
	}
}

static void dump(struct context *context) {
	struct user_data *d = context->user_data;
	FILE *dump_file = fopen(DUMP_FILE_DST, "a");
	if (dump_file == NULL) {
		ulog(LLOG_ERROR, "Can't open Majordomo dump file %s", DUMP_FILE_DST);
		//Nothing to do now
		return;
	}

	//IPv6 has longer strings, use them - don't care about few bytes overhead
	char src_str[INET6_ADDRSTRLEN];
	char dst_str[INET6_ADDRSTRLEN];
	char *app_protocol;

	for (struct comm_item *it = d->communication->head; it; it = it->next) {
		get_string_from_raw_bytes(it->key.from, it->key.from_addr_len, src_str);
		get_string_from_raw_bytes(it->key.to, it->key.to_addr_len, dst_str);

		if (it->key.protocol == 'T') {
			app_protocol = "TCP";
		} else if (it->key.protocol == 'U') {
			app_protocol = "UDP";
		}

		fprintf(dump_file, "%s,%s,%s,%" PRIu16 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n", app_protocol, src_str, dst_str, it->key.port, it->value.packets_count, it->value.packets_size, it->value.data_size);
	}

	for (struct src_item *it = d->sources->head; it; it = it->next) {
		char src_str[INET6_ADDRSTRLEN];
		get_string_from_raw_bytes(it->from.addr, it->from.addr_len, src_str);
		fprintf(dump_file, "%s,%s,%s,%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n", "both", src_str, "all", "all", it->other.packets_count, it->other.packets_size, it->other.data_size);
	}

	//Cleanup
	//Reinit lists
	d->communication->head = NULL;
	d->communication->tail = NULL;
	d->communication->count = 0;
	d->sources->head = NULL;
	d->sources->tail = NULL;
	d->sources->count = 0;
	//Drop dumped data
	mem_pool_reset(d->list_pool);
	//Close dump file
	fclose(dump_file);
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
		.communication = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data->communication),
		.sources = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data->sources),
		.list_pool = loop_pool_create(context->loop, context, "Majordomo linked-lists pool"),
		.timeout = loop_timeout_add(context->loop, DUMP_TIMEOUT, context, NULL, scheduled_dump)
	};
	*context->user_data->communication = (struct comm_items) {
		.count = 0
	};
	*context->user_data->sources = (struct src_items) {
		.count = 0
	};
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
		.finish_callback = destroy
	};
	return &plugin;
}

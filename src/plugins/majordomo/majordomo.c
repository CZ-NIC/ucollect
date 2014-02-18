/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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
#define SOURCE_SIZE_LIMIT 5000
//in ms - 1 minute
#define DUMP_TIMEOUT 60000

#define KEYS_ADDR_LEN 16

struct key {
	unsigned char from[KEYS_ADDR_LEN];
	unsigned char to[KEYS_ADDR_LEN];
	unsigned char addr_len;
	char protocol;
	uint16_t port;
};

struct src_key {
	unsigned char addr[KEYS_ADDR_LEN];
	unsigned char addr_len;
};

struct value {
	unsigned long long int packets_count;
	unsigned long long int packets_size;
	unsigned long long int data_size;
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
	unsigned long long int items_in_comm_list;
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
#define LIST_HEAD head
#define LIST_TAIL tail
#define LIST_NEXT next
#define LIST_PREV prev
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_REMOVE
#include "../../core/link_list.h"


#define LIST_NODE struct src_item
#define LIST_BASE struct src_items
#define LIST_NAME(X) src_items_##X
#define LIST_COUNT count
#define LIST_HEAD head
#define LIST_TAIL tail
#define LIST_NEXT next
#define LIST_PREV prev
#define LIST_WANT_APPEND_POOL
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
	}
}

static bool key_equals(struct comm_item *item, unsigned char *from, unsigned char *to, char protocol, uint16_t port, unsigned char addr_len) {
	if (item->key.addr_len == addr_len && item->key.protocol == protocol && item->key.port == port && memcmp(item->key.from, from, addr_len) == 0 && memcmp(item->key.to, to, addr_len) == 0 ) {
		return true;
	}

	return false;
}

static struct comm_item *find_item(struct comm_items *comm, unsigned char *from, unsigned char *to, unsigned char protocol, uint16_t port, unsigned char addr_len) {
	for (struct comm_item *it = comm->head; it; it = it->next) {
		if (key_equals(it, from, to, protocol, port, addr_len)) {
			return it;
		}
	}

	return NULL;
}

static struct src_item *find_src(struct src_items *sources, unsigned char *from, unsigned char addr_len) {
	for (struct src_item *it = sources->head; it; it = it->next) {
		if (it->from.addr_len == addr_len && memcmp(it->from.addr, from, addr_len) == 0) {
			return it;
		}
	}

	return NULL;
}

static struct comm_item *create_comm_item(struct comm_items *communication, struct mem_pool *list_pool, const struct packet_info *info) {
	struct comm_item *item;
	//Create item
	item = items_append_pool(communication, list_pool);
	//update position
	items_remove(communication, item);
	items_insert_after(communication, item, NULL); //NULL == insert after head
	//Fill item's data
	memcpy(item->key.from, info->addresses[END_SRC], info->addr_len);
	memcpy(item->key.to, info->addresses[END_DST], info->addr_len);
	item->key.protocol = info->app_protocol;
	item->key.port = info->ports[END_DST];
	item->key.addr_len = info->addr_len;
	item->value.packets_count = 1;
	item->value.packets_size = info->length;
	item->value.data_size = info->length - info->hdr_length;

	return item;
}

void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *d = context->user_data;
	//Filter some useless packets
	if (info->next) {
		// It's wrapper around some other real packet. We're not interested in the envelope.
		packet_handle(context, info->next);
		return;
	}

	if (info->direction != DIR_OUT) {
		//Only outgoing packets
		return;
	}

	if (info->app_protocol != 'T' && info->app_protocol != 'U') {
		//Interested only in UDP and TCP packets
		return;
	}

	//Check situation about this packet
	struct comm_item *item = find_item(d->communication, (unsigned char *) info->addresses[END_SRC], (unsigned char *) info->addresses[END_DST], info->app_protocol, info->ports[END_DST], info->addr_len);
	struct src_item *src = find_src(d->sources, (unsigned char *) info->addresses[END_SRC], (unsigned char) info->addr_len);

	//And make decisions

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
			item = create_comm_item(d->communication, d->list_pool, info);
			//Create source record
			src = src_items_append_pool(d->sources, d->list_pool);
			//Fill source data
			memcpy(src->from.addr, info->addresses[END_SRC], info->addr_len);
			src->from.addr_len = info->addr_len;
			src->other.packets_count = 0;
			src->other.packets_size = 0;
			src->other.data_size = 0;
			src->items_in_comm_list = 1;
			//Add link into item
			item->src_parent = src;

		} else {
			//Source has some records; check its limit
			if (src->items_in_comm_list < SOURCE_SIZE_LIMIT) {
				item = create_comm_item(d->communication, d->list_pool, info);
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
		get_string_from_raw_bytes(it->key.from, it->key.addr_len, src_str);
		get_string_from_raw_bytes(it->key.to, it->key.addr_len, dst_str);

		if (it->key.protocol == 'T') {
			app_protocol = "TCP";
		} else if (it->key.protocol == 'U') {
			app_protocol = "UDP";
		}

		fprintf(dump_file, "%s,%s,%s,%" PRIu16 ",%llu,%llu,%llu\n", app_protocol, src_str, dst_str, it->key.port, it->value.packets_count, it->value.packets_size, it->value.data_size);
	}

	for (struct src_item *it = d->sources->head; it; it = it->next) {
		char src_str[INET6_ADDRSTRLEN];
		get_string_from_raw_bytes(it->from.addr, it->from.addr_len, src_str);
		fprintf(dump_file, "%s,%s,%s,%s,%llu,%llu,%llu\n", "both", src_str, "all", "all", it->other.packets_count, it->other.packets_size, it->other.data_size);
	}

	//Cleanup
	//Reiniti lists
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
		.list_pool = mem_pool_create("Majordomo linked-lists pool"),
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
	//Cancel scheduled dump and do it manualy
	loop_timeout_cancel(context->loop, context->user_data->timeout);
	dump(context);
	//This command shoul'd be the last
	mem_pool_destroy(context->user_data->list_pool);
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

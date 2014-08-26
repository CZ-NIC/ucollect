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

#include "filter.h"
#include "flow.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/util.h"
#include "../../core/trie.h"

#include <assert.h>
#include <arpa/inet.h>
#include <string.h>

struct trie_data {
	struct flow flow;
};

struct user_data {
	struct mem_pool *conf_pool, *flow_pool;
	struct trie *trie;
	struct filter *filter;
	uint32_t conf_id;
	uint32_t max_flows;
	uint32_t timeout;
	uint32_t min_packets;
	size_t timeout_id;
	bool configured;
	bool timeout_scheduled;
};

struct flush_data {
	size_t size;
	size_t i;
	size_t *sizes;
	size_t pos;
	uint32_t min_packets;
	uint8_t *output;
};

static void get_size(const uint8_t *key, size_t key_size, struct trie_data *flow, void *userdata) {
	struct flush_data *data = userdata;
	(void)key;
	(void)key_size;
	if (flow && flow->flow.count[0] + flow->flow.count[1] >= data->min_packets) {
		data->size += data->sizes[data->i ++] = flow_size(&flow->flow);
	} else {
		// Empty flow, created when the limit is reached.
		data->sizes[data->i ++] = 0;
	}
}

static void format_flow(const uint8_t *key, size_t key_size, struct trie_data *flow, void *userdata) {
	struct flush_data *data = userdata;
	(void)key;
	(void)key_size;
	if (flow && flow->flow.count[0] + flow->flow.count[1] >= data->min_packets) {
		flow_render(data->output + data->pos, data->sizes[data->i], &flow->flow);
		data->pos += data->sizes[data->i ++];
	} else {
		// Empty flow, skip
		data->i ++;
	}
}

static void flush(struct context *context) {
	struct user_data *u = context->user_data;
	size_t header = sizeof(char) + sizeof(uint32_t) + sizeof(uint64_t);
	struct flush_data d = {
		.sizes = mem_pool_alloc(context->temp_pool, trie_size(u->trie) * sizeof *d.sizes),
		.pos = header,
		.min_packets = u->min_packets
	};
	ulog(LLOG_INFO, "Sending %zu flows\n", trie_size(u->trie));
	trie_walk(u->trie, get_size, &d, context->temp_pool);
	assert(d.i == trie_size(u->trie));
	size_t total_size = header + d.size;
	d.output = mem_pool_alloc(context->temp_pool, total_size);
	*d.output = 'D';
	uint32_t conf_id = htonl(u->conf_id);
	memcpy(d.output + sizeof(char), &conf_id, sizeof conf_id);
	uint64_t now = htobe64(loop_now(context->loop));
	memcpy(d.output + sizeof(char) + sizeof conf_id, &now, sizeof now);
	d.i = 0;
	trie_walk(u->trie, format_flow, &d, context->temp_pool);
	assert(d.i == trie_size(u->trie));
	assert(d.pos == total_size);
	uplink_plugin_send_message(context, d.output, total_size);
	mem_pool_reset(u->flow_pool);
	u->trie = trie_alloc(u->flow_pool);
}

static void schedule_timeout(struct context *context);

static void timeout_fired(struct context *context, void *unused_data, size_t unused_id) {
	(void) unused_data;
	(void) unused_id;
	struct user_data *u = context->user_data;
	assert(u->timeout_scheduled);
	u->timeout_scheduled = false;
	flush(context);
	schedule_timeout(context);
}

static void schedule_timeout(struct context *context) {
	struct user_data *u = context->user_data;
	assert(!u->timeout_scheduled);
	u->timeout_id = loop_timeout_add(context->loop, u->timeout, context, NULL, timeout_fired);
	u->timeout_scheduled = true;
}

static void configure(struct context *context, uint32_t conf_id, uint32_t max_flows, uint32_t timeout, uint32_t min_packets, const uint8_t *filter_desc, size_t filter_size) {
	ulog(LLOG_INFO, "Received configuration %u (max. %u flows, %u ms timeout)\n", (unsigned)conf_id, (unsigned)max_flows, (unsigned)timeout);
	struct user_data *u = context->user_data;
	if (u->configured && u->conf_id != conf_id) {
		ulog(LLOG_DEBUG, "Replacing old configuration\n");
		// Switching configuration, so flush the old data
		flush(context);
		assert(u->timeout_scheduled);
		loop_timeout_cancel(context->loop, u->timeout_id);
		u->timeout_scheduled = false;
		mem_pool_reset(u->conf_pool);
	}
	u->conf_id = conf_id;
	u->max_flows = max_flows;
	u->timeout = timeout;
	if (!u->timeout_scheduled)
		schedule_timeout(context);
	u->filter = filter_parse(u->conf_pool, filter_desc, filter_size);
	u->min_packets = min_packets;
	u->configured = true;
}

static void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *u = context->user_data;
	if (!u->configured)
		return; // We are just starting up and waiting for server to send us what to collect
	while (info->next)
		info = info->next;
	if (info->direction >= DIR_UNKNOWN)
		return; // Broken packet, we don't want that
	if (info->layer != 'I' || (info->ip_protocol != 4 && info->ip_protocol != 6) || (info->app_protocol != 'T' && info->app_protocol != 'U'))
		return; // Something we don't track
	if (!filter_apply(context->temp_pool, u->filter, info))
		return; // This packet is not interesting
	size_t key_size;
	uint8_t *key = flow_key(info, &key_size, context->temp_pool);
	struct trie_data **data = trie_index(u->trie, key, key_size);
	assert(data);
	if (!*data) {
		// We don't have this flow yet
		if (trie_size(u->trie) == u->max_flows) {
			// We are full, no space for another flow
			flush(context);
			assert(u->timeout_scheduled);
			loop_timeout_cancel(context->loop, u->timeout_id);
			u->timeout_scheduled = false;
			schedule_timeout(context);
			// We destroyed the previous trie, index the new one
			data = trie_index(u->trie, key, key_size);
		}
		ulog(LLOG_DEBUG_VERBOSE, "Creating new flow\n");
		*data = mem_pool_alloc(u->flow_pool, sizeof **data);
		flow_parse(&(*data)->flow, info);
	}
	// Add to statisticts
	struct flow *f = &(*data)->flow;
	f->count[info->direction] ++;
	f->size[info->direction] += info->length;
	f->last_time[info->direction] = loop_now(context->loop);
	if (!f->first_time[info->direction])
		f->first_time[info->direction] = loop_now(context->loop);
}

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	struct mem_pool *flow_pool = loop_pool_create(context->loop, context, "Flow pool");
	*context->user_data = (struct user_data) {
		.conf_pool = loop_pool_create(context->loop, context, "Flow conf pool"),
		.flow_pool = flow_pool,
		.trie = trie_alloc(flow_pool)
	};
}

static void connected(struct context *context) {
	// Ask for config.
	uplink_plugin_send_message(context, "C", 1);
}

struct config {
	uint32_t conf_id;
	uint32_t max_flows;
	uint32_t timeout;
	uint32_t min_packets;
};

static void config_parse(struct context *context, const uint8_t *data, size_t length) {
	struct config config;
	assert(length >= sizeof config);
	memcpy(&config, data, sizeof config); // Copy out, because of alignment
	configure(context, ntohl(config.conf_id), ntohl(config.max_flows), ntohl(config.timeout), ntohl(config.min_packets), data + sizeof config, length - sizeof config);
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	assert(length);
	switch (*data) {
		case 'F': // Force-flush flows. Probably unused now, but ready in case we find need.
			assert(length == 1);
			flush(context);
			break;
		case 'C': // Config. Either requested, or flushed. But accept it anyway.
			config_parse(context, data + 1, length - 1);
			break;
		default:
			ulog(LLOG_WARN, "Unknown message opcode '%c' (%hhu), ignoring\n", *data, *data);
			break;
	}
}

#ifdef STATIC
struct plugin *plugin_info_flow(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.packet_callback = packet_handle,
		.init_callback = initialize,
		.uplink_connected_callback = connected,
		.uplink_data_callback = communicate,
		.name = "Flow"
	};
	return &plugin;
}

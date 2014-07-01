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

#include <assert.h>
#include <arpa/inet.h>
#include <string.h>

struct user_data {
	struct mem_pool *conf_pool;
	struct flow *flows; // TODO: Some kind of hashing here?
	struct filter *filter;
	uint32_t conf_id;
	uint32_t max_flows;
	uint32_t flow_count;
	uint32_t timeout;
	size_t timeout_id;
	bool configured;
	bool timeout_scheduled;
};

static void flush(struct context *context) {
	struct user_data *u = context->user_data;
	size_t size = 0;
	size_t *sizes = mem_pool_alloc(context->temp_pool, u->flow_count * sizeof *sizes);
	ulog(LLOG_DEBUG, "Sending %zu flows\n", (size_t)u->flow_count);
	for (size_t i = 0; i < u->flow_count; i ++)
		size += sizes[i] = flow_size(&u->flows[i]);
	size_t header = sizeof(char) + sizeof(uint32_t) + sizeof(uint64_t);
	size_t total_size = size + header;
	uint8_t *message = mem_pool_alloc(context->temp_pool, total_size);
	*message = 'D';
	uint32_t conf_id = htonl(u->conf_id);
	memcpy(message + sizeof(char), &conf_id, sizeof conf_id);
	uint64_t now = htobe64(loop_now(context->loop));
	memcpy(message + sizeof(char) + sizeof conf_id, &now, sizeof now);
	size_t pos = 0;
	for (size_t i = 0; i < u->flow_count; i ++) {
		flow_render(message + pos + header, sizes[i], &u->flows[i]);
		pos += sizes[i];
	}
	uplink_plugin_send_message(context, message, total_size);
	u->flow_count = 0;
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

static void configure(struct context *context, uint32_t conf_id, uint32_t max_flows, uint32_t timeout, const uint8_t *filter_desc, size_t filter_size) {
	ulog(LLOG_INFO, "Received configuration %u (max. %u flows, %u ms timeout)\n", (unsigned)conf_id, (unsigned)max_flows, (unsigned)timeout);
	struct user_data *u = context->user_data;
	if (u->configured) {
		flush(context);
		assert(u->timeout_scheduled);
		loop_timeout_cancel(context->loop, u->timeout_id);
		u->timeout_scheduled = false;
		mem_pool_reset(u->conf_pool);
	}
	u->conf_id = conf_id;
	u->flows = mem_pool_alloc(u->conf_pool, max_flows * sizeof *u->flows);
	u->max_flows = max_flows;
	u->timeout = timeout;
	schedule_timeout(context);
	u->filter = filter_parse(u->conf_pool, filter_desc, filter_size);
	u->configured = true;
}

static void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *u = context->user_data;
	if (!u->configured)
		return; // We are just starting up and waiting for server to send us what to collect
	while (info->next)
		info = info->next;
	if (!filter_apply(u->filter, info))
		return; // This packet is not interesting
	if (info->direction >= DIR_UNKNOWN)
		return; // Broken packet, we don't want that
	if (info->layer != 'I' || (info->ip_protocol != 4 && info->ip_protocol != 6) || (info->app_protocol != 'T' && info->app_protocol != 'U'))
		return; // Something we don't track
	size_t idx = u->max_flows;
	struct flow tmp_flow;
	flow_parse(&tmp_flow, info);
	for (size_t i = 0; i < u->flow_count; i ++)
		if (flow_cmp(&u->flows[i], &tmp_flow)) {
			idx = i;
			break;
		}
	if (idx == u->max_flows) {
		// The flow is not there, create a new one
		if (u->flow_count == u->max_flows) {
			// The table is full, flush it.
			flush(context);
			assert(u->timeout_scheduled);
			loop_timeout_cancel(context->loop, u->timeout_id);
			u->timeout_scheduled = false;
			schedule_timeout(context);
		}
		// Put the flow into the table
		idx = u->flow_count ++;
		flow_parse(&u->flows[idx], info);
	}
	// Add to statisticts
	u->flows[idx].count[info->direction] ++;
	u->flows[idx].size[info->direction] += info->length;
	u->flows[idx].last_time[info->direction] = loop_now(context->loop);
	if (!u->flows[idx].first_time[info->direction])
		u->flows[idx].first_time[info->direction] = loop_now(context->loop);
}

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.conf_pool = loop_pool_create(context->loop, context, "Flow conf pool")
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
};

static void config_parse(struct context *context, const uint8_t *data, size_t length) {
	struct config config;
	assert(length >= sizeof config);
	memcpy(&config, data, sizeof config); // Copy out, because of alignment
	configure(context, ntohl(config.conf_id), ntohl(config.max_flows), ntohl(config.timeout), data + sizeof config, length - sizeof config);
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

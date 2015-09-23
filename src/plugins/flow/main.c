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

#include "filter.h"
#include "flow.h"

#define PLUGLIB_DO_IMPORT PLUGLIB_STRUCTS
#include "../../libs/diff_store/diff_store.h"

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
	bool timeout_missed;
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

static bool flush(struct context *context, bool force) {
	if (!force && !uplink_connected(context->uplink))
		return false; // Don't try to send if we are not connected.
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
	if (!uplink_plugin_send_message(context, d.output, total_size) && !force)
		return false; // Don't clean the data if we failed to send. But do clean them if the force is in effect, to not overflow the limit by too much
	mem_pool_reset(u->flow_pool);
	u->trie = trie_alloc(u->flow_pool);
	u->timeout_missed = false;
	return true;
}

static void schedule_timeout(struct context *context);

static void timeout_fired(struct context *context, void *unused_data, size_t unused_id) {
	(void) unused_data;
	(void) unused_id;
	struct user_data *u = context->user_data;
	assert(u->timeout_scheduled);
	u->timeout_scheduled = false;
	u->timeout_missed = !flush(context, u->timeout_missed);
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
		flush(context, true);
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
		if (trie_size(u->trie) >= u->max_flows) {
			// We are full, no space for another flow
			flush(context, trie_size(u->trie) >= 2 * u->max_flows);
			assert(u->timeout_scheduled);
			loop_timeout_cancel(context->loop, u->timeout_id);
			u->timeout_scheduled = false;
			schedule_timeout(context);
			// We may have destroyed the previous trie, index the new one
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
	if (info->app_protocol == 'T' && (info->tcp_flags & TCP_SYN) && !(info->tcp_flags & TCP_ACK))
		f->seen_flow_start[info->direction] = true;
}

static void connected(struct context *context) {
	// Ask for config.
	uplink_plugin_send_message(context, "C", 1);
	struct user_data *u = context->user_data;
	if (!u->configured)
		return; // If we never configured, there's nothing to send anyway
	if (u->timeout_missed || trie_size(u->trie) >= u->max_flows)
		// Try resending if there was a missed send attempt
		flush(context, false);
}

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	struct mem_pool *flow_pool = loop_pool_create(context->loop, context, "Flow pool");
	*context->user_data = (struct user_data) {
		.conf_pool = loop_pool_create(context->loop, context, "Flow conf pool"),
		.flow_pool = flow_pool,
		.trie = trie_alloc(flow_pool)
	};
	/*
	 * Ask for config right away. In case we get reloaded, we won't
	 * get the connected callback, because we are already connected.
	 *
	 * On the other hand, if we are not connected, this message gets
	 * blackholed, but we get the callback later.
	 */
	connected(context);
}

struct config {
	uint32_t conf_id;
	uint32_t max_flows;
	uint32_t timeout;
	uint32_t min_packets;
};

static void config_parse(struct context *context, const uint8_t *data, size_t length) {
	struct config config;
	sanity(length >= sizeof config, "Flow config message too short, expected %zu bytes, got %zu\n", sizeof config, length);
	memcpy(&config, data, sizeof config); // Copy out, because of alignment
	configure(context, ntohl(config.conf_id), ntohl(config.max_flows), ntohl(config.timeout), ntohl(config.min_packets), data + sizeof config, length - sizeof config);
}

static void handle_filter_action(struct context *context, enum diff_store_action action, const char *name, uint32_t epoch, uint32_t old_version, uint32_t new_version) {
	switch (action) {
		case DIFF_STORE_UNKNOWN:
		case DIFF_STORE_NO_ACTION:
			break;
		case DIFF_STORE_CONFIG_RELOAD:
			uplink_plugin_send_message(context, "C", 1);
			break;
		case DIFF_STORE_INCREMENTAL:
		case DIFF_STORE_FULL: {
			bool full = (action == DIFF_STORE_FULL);
			size_t len = 1 + 1 + sizeof(uint32_t) + strlen(name) + (2 + !full) * sizeof(uint32_t);
			uint8_t *message = mem_pool_alloc(context->temp_pool, len);
			uint8_t *pos = message;
			size_t rest = len;
			*(pos ++) = 'U';
			rest --;
			*(pos ++) = full;
			rest --;
			uplink_render_string(name, strlen(name), &pos, &rest);
			uplink_render_uint32(epoch, &pos, &rest);
			if (!full)
				uplink_render_uint32(old_version, &pos, &rest);
			uplink_render_uint32(new_version, &pos, &rest);
			assert(!rest);
			uplink_plugin_send_message(context, message, len);
			break;
		}
	}
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	sanity(length, "A zero length message delivered to the flow plugin\n");
	switch (*data) {
		case 'F': // Force-flush flows. Probably unused now, but ready in case we find need.
			sanity(length == 1, "Extra data in the flow flush message, %zu extra bytes\n", length - 1);
			flush(context, false);
			break;
		case 'C': // Config. Either requested, or flushed. But accept it anyway.
			config_parse(context, data + 1, length - 1);
			break;
		case 'U': {// Offer of an update of a differential filter
			if (!context->user_data->configured)
				return; // The basic config is not there yet. No filter to apply the diff to.
			data ++;
			length --;
			char *name = uplink_parse_string(context->temp_pool, &data, &length);
			if (!name) {
				ulog(LLOG_ERROR, "Update message too short to contain filter name\n");
				abort();
			}
			uint32_t epoch = uplink_parse_uint32(&data, &length);
			uint32_t version = uplink_parse_uint32(&data, &length);
			if (length)
				ulog(LLOG_WARN, "Extra data at the end of diff-filter update message (%zu bytes: %s)\n", length, mem_pool_hex(context->temp_pool, data, length));
			uint32_t orig_version;
			ulog(LLOG_DEBUG, "Received version update of diff filter %s: %u %u\n", name, epoch, version);
			enum diff_store_action action = filter_action(context->user_data->filter, name, epoch, version, &orig_version);
			if (action == DIFF_STORE_UNKNOWN)
				ulog(LLOG_WARN, "Update for unknown filter %s received\n", name);
			handle_filter_action(context, action, name, epoch, orig_version, version);
			break;
		}
		case 'D': { // difference to apply to a filter (may be asked for or not)
			if (!context->user_data->configured)
				return; // The basic config is not there yet. No filter to apply the diff to.
			data ++;
			length --;
			char *name = uplink_parse_string(context->temp_pool, &data, &length);
			if (!name) {
				ulog(LLOG_ERROR, "Diff message too short to contain filter name\n");
				abort();
			}
			if (!length) {
				ulog(LLOG_ERROR, "Diff message too short, missing update fullness flag\n");
				abort();
			}
			bool full = *data;
			length --;
			data ++;
			ulog(LLOG_DEBUG_VERBOSE, "Length: %zu\n", length);
			uint32_t epoch = uplink_parse_uint32(&data, &length);
			uint32_t from = 0;
			if (!full)
				from = uplink_parse_uint32(&data, &length);
			uint32_t to = uplink_parse_uint32(&data, &length);
			uint32_t orig_version;
			ulog(LLOG_DEBUG_VERBOSE, "Length: %zu\n", length);
			enum diff_store_action action = filter_diff_apply(context->temp_pool, context->user_data->filter, name, full, epoch, from, to, data, length, &orig_version);
			switch (action) {
				case DIFF_STORE_UNKNOWN:
					ulog(LLOG_WARN, "Diff for unknown filter %s received \n", name);
					break;
				case DIFF_STORE_INCREMENTAL:
				case DIFF_STORE_FULL:
					ulog(LLOG_WARN, "Filter %s out of sync, dropping diff\n", name);
					break;
				default:;
			}
			handle_filter_action(context, action, name, epoch, orig_version, to);
			break;
		}
		default:
			ulog(LLOG_WARN, "Unknown message opcode '%c' (%hhu), ignoring\n", *data, *data);
			break;
	}
}

#ifndef STATIC
unsigned api_version() {
	return UCOLLECT_PLUGIN_API_VERSION;
}
#endif

#ifdef STATIC
struct plugin *plugin_info_flow(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct pluglib_import *imports[] = {
		&diff_addr_store_init_import,
		&diff_addr_store_action_import,
		&diff_addr_store_apply_import,
		NULL
	};
	static struct plugin plugin = {
		.packet_callback = packet_handle,
		.init_callback = initialize,
		.uplink_connected_callback = connected,
		.uplink_data_callback = communicate,
		.name = "Flow",
		.version = 2,
		.imports = imports
	};
	return &plugin;
}

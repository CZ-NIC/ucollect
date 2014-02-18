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

#include "../../core/plugin.h"
#include "../../core/packet.h"
#include "../../core/context.h"
#include "../../core/loop.h"
#include "../../core/mem_pool.h"
#include "../../core/util.h"

#include <string.h>

// Warn at most every 15 minutes
#define WARN_TIMEOUT 15 * 60 * 1000

// At least so many packets before actually warning
#define WARN_COUNT 10

enum warn_type {
	W_PPPOE,
	W_LAYER,
	W_DIRECTION,
	W_MAX
};

struct user_data {
	size_t count;
	uint64_t start;
};

void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, W_MAX * sizeof *context->user_data);
	memset(context->user_data, 0, W_MAX * sizeof *context->user_data);
}

#define WARN(WTYPE, ...) do {\
	uint64_t now = loop_now(context->loop); \
	if (now - WARN_TIMEOUT > context->user_data[WTYPE].start) { \
		context->user_data[WTYPE] = (struct user_data) { \
			.count = 1, \
			.start = now \
		}; \
	} else if (++ context->user_data[WTYPE].count == WARN_COUNT) { \
		const char *message = mem_pool_printf(context->temp_pool, __VA_ARGS__); \
		ulog(LLOG_WARN, "Possible misconfiguration on interface %s: %s\n", info->interface, message); \
	} \
} while (0)

static void packet_handle(struct context *context, const struct packet_info *info) {
	for (; info; info = info->next) {
		if (info->layer == '?')
			WARN(W_LAYER, "packet on unknown layer %d", info->layer_raw);
		if (info->direction >= DIR_UNKNOWN)
			WARN(W_DIRECTION, "packet of unknown direction");
		if (info->app_protocol == 'P')
			WARN(W_PPPOE, "a PPPoE packet seen");
	}
}

#ifdef STATIC
struct plugin *plugin_info_badconf(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Badconf",
		.packet_callback = packet_handle,
		.init_callback = initialize
	};
	return &plugin;
}

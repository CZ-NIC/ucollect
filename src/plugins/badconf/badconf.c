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

// Warn at most every 15 minutes
#define WARN_TIMEOUT 15 * 60 * 1000

enum warn_type {
	W_PPPOE,
	W_LAYER,
	W_DIRECTION,
	W_MAX
};

static uint64_t warn_times[W_MAX];

#define WARN(WTYPE, ...) do {\
	uint64_t now = loop_now(context->loop); \
	if (now - WARN_TIMEOUT > warn_times[WTYPE]) { \
		warn_times[WTYPE] = now; \
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
		.packet_callback = packet_handle
	};
	return &plugin;
}

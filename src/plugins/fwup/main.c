/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/uplink.h"
#include "../../core/util.h"

struct user_data {
	struct mem_pool *conf_pool;
	bool configured;
};

static void connected(struct context *context) {
	// Just ask for config
	uplink_plugin_send_message(context, "C", 1);
}

static void initialize(struct context *context) {
	struct user_data *u = context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*u = (struct user_data) {
		.conf_pool = loop_pool_create(context->loop, context, "FWUp config pool")
	};
	// Ask for config, if already connected (unlikely, but then, the message will get blackholed).
	connected(context);
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	sanity(length, "A zero-length message delivered to the FWUp plugin\n");
	switch (*data) {
		default:
			ulog(LLOG_WARN, "Unknown message opcode on FWUp: '%c' (%hhu), ignoring\n", *data, *data);
			break;
	}
}

#ifdef STATIC
#error "Fwup is not ready for static linkage. Nobody needed it."
#else
struct plugin *plugin_info(void) {
	static struct plugin plugin = {
		.name = "FWUp",
		.version = 1,
		.init_callback = initialize,
		.uplink_data_callback = communicate,
		.uplink_connected_callback = connected
	};
	return &plugin;
}

unsigned api_version() {
	return UCOLLECT_PLUGIN_API_VERSION;
}
#endif

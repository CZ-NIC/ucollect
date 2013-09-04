/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC

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
#include "../../core/loop.h"
#include "../../core/context.h"

#include <stdlib.h>

/*
 * WARNING: This is a testing plugin only. The only thing it does is to crash
 * after 2 seconds of runtime. It is not expected to be used in production.
 */

static void crash(struct context *context_unused, void *data_unused, size_t id_unused) {
	(void) context_unused;
	(void) data_unused;
	(void) id_unused;
	abort();
}

static void prepare_crash(struct context *context) {
	loop_timeout_add(context->loop, 2000, context, NULL, crash);
}

static void packet_crash(struct context *context_unused, const struct packet_info *info_unused) {
	(void) context_unused;
	(void) info_unused;
	abort();
}

static void data_crash(struct context *context_unused, const uint8_t *data_unused, size_t length_unused) {
	(void) context_unused;
	(void) data_unused;
	(void) length_unused;
	abort();
}

struct plugin *plugin_info(void) {
	static struct plugin plugin = {
		.name = "Crash",
		.uplink_data_callback = data_crash,
		.init_callback = prepare_crash,
		.packet_callback = packet_crash
	};
	return &plugin;
}

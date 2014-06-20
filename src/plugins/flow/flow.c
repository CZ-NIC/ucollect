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

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"

#include <stdbool.h>
#include <assert.h>

struct flow  {

};

struct user_data {
	struct mem_pool *conf_pool;
	struct flow *flows;
	uint32_t timeout;
	size_t timeout_id;
	uint32_t max_flows;
	bool configured;
	bool timeout_scheduled;
};

static void flush(struct context *context) {
	struct user_data *u = context->user_data;
}

static void schedule_timeout(struct context *context);

static void timeout_fired(struct context *context, void *unused_data, size_t unused_id) {
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

static void configure(struct context *context, uint32_t max_flows, uint32_t timeout) {
	// TODO: Filters go here
	struct user_data *u = context->user_data;
	if (u->configured) {
		flush(context);
		assert(u->timeout_scheduled);
		loop_timeout_cancel(context->loop, u->timeout_id);
		u->timeout_scheduled = false;
		mem_pool_reset(u->conf_pool);
	}
	u->flows = mem_pool_alloc(u->conf_pool, max_flows * sizeof *u->flows);
	u->max_flows = max_flows;
	u->timeout = timeout;
	schedule_timeout(context);
	u->configured = true;
}

static void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *u = context->user_data;
	if (!u->configured)
		return;
}

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.conf_pool = loop_pool_create(context->loop, context, "Flow conf pool")
	};
	// FIXME: This is just for testing purposes
	configure(context, 10000, 1000 * 900);
}

#ifdef STATIC
struct plugin *plugin_info_flow(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.packet_callback = packet_handle,
		.init_callback = initialize,
		.name = "Flow"
	};
	return &plugin;
}

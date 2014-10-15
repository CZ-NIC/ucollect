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

#include "server.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/loop.h"

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

struct fd_tag {
	const struct server_desc *desc;
	struct server_data *server;
	struct conn_data *conn;
	int fd, candidate;
	uint16_t port, port_candidate;
	bool accept_here; // When the thing is readable, call accept here instead of server_ready
};

struct user_data {
	struct fd_tag *tags;
	size_t *tag_indices;
	size_t server_count, tag_count;
	struct mem_pool *pool;
};

static void initialize(struct context *context) {
	struct user_data *u = context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*u = (struct user_data) {
		.pool = loop_pool_create(context->loop, context, "Fake pool")
	};
	size_t server_count = 0, tag_count = 0;
	for (const struct server_desc *desc = server_descs; desc->name; desc++) {
		server_count ++;
		tag_count += 1 + desc->max_conn;
	}
	u->tags = mem_pool_alloc(context->permanent_pool, tag_count * sizeof *u->tags);
	memset(u->tags, 0, tag_count * sizeof * u->tags);
	u->tag_indices = mem_pool_alloc(context->permanent_pool, (server_count + 1) * sizeof *u->tag_indices);
	size_t pos = 0, i = 0;
	for (const struct server_desc *desc = server_descs; desc->name; desc++) {
		u->tags[pos].desc = desc;
		u->tag_indices[i ++] = pos;
		if (desc->server_alloc_cb)
			u->tags[pos].server = desc->server_alloc_cb(context, u->pool, desc);
		if (desc->max_conn) {
			for (size_t j = pos; j < pos + 1 + desc->max_conn; j ++) {
				// The description and server are shared between all the connections
				u->tags[j].desc = desc;
				u->tags[j].server = u->tags[pos].server;
				// But a connection structure is for each of them
				if (desc->conn_alloc_cb)
					u->tags[j].conn = desc->conn_alloc_cb(context, u->pool, u->tags[pos].server);
			}
			u->tags[pos].accept_here = true;
		} else if (desc->conn_alloc_cb)
			u->tags[pos].conn = desc->conn_alloc_cb(context, u->pool, u->tags[pos].server);
		pos += 1 + desc->max_conn;
	}
	// Bumper
	u->tag_indices[i] = pos;
	u->server_count = server_count;
	u->tag_count = tag_count;
}

#ifdef STATIC
struct plugin *plugin_info_fake(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Fake",
		.version = 1,
		.init_callback = initialize
	};
	return &plugin;
}

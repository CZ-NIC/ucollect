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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

static bool config(struct context *context) {
	struct user_data *u = context->user_data;
	for (size_t i = 0; i < u->server_count; i ++) {
		struct fd_tag *t = &u->tags[u->tag_indices[i]];
		char *opt_name = mem_pool_printf(context->temp_pool, "%s_port", t->desc->name);
		const struct config_node *opt = loop_plugin_option_get(context, opt_name);
		uint16_t port;
		if (opt) {
			if (opt->value_count != 1) {
				ulog(LLOG_ERROR, "Option %s must have single value, not %zu\n", opt_name, opt->value_count);
				return false;
			}
			if (!*opt->values[0]) {
				ulog(LLOG_ERROR, "Option %s is empty\n", opt_name);
				return false;
			}
			char *end;
			long p = strtol(opt->values[0], &end, 10);
			if (end && *end) {
				ulog(LLOG_ERROR, "Option %s must be integer\n", opt_name);
				return false;
			}
			if (!p || p >= 65536) {
				ulog(LLOG_ERROR, "Option %s of value %ld out of range (valid ports are 1-65535)\n", opt_name, p);
				return false;
			}
			port = p;
		} else {
			port = t->desc->default_port;
			ulog(LLOG_WARN, "Option %s not present, using default %u\n", opt_name, (unsigned)port);
		}
		t->port_candidate = port;
		if (port == t->port) {
			t->candidate = t->fd;
		} else if (port) {
			int sock = socket(AF_INET6, t->desc->sock_type, 0);
			if (sock == -1) {
				ulog(LLOG_ERROR, "Error allocating socket for fake server %s: %s\n", t->desc->name, strerror(errno));
				return false;
			}
			// Register it right away, so it is closed in case of plugin crash
			loop_plugin_register_fd(context, sock, t);
			struct sockaddr_in6 addr = {
				.sin6_family = AF_INET6,
				.sin6_port = htons(port),
				.sin6_addr = IN6ADDR_ANY_INIT
			};
			if (bind(sock, (const struct sockaddr *)&addr, sizeof addr) == -1) {
				ulog(LLOG_ERROR, "Couldn't bind fake server %s socket %d to port %u: %s\n", t->desc->name, sock, (unsigned)port, strerror(errno));
				loop_plugin_unregister_fd(context, sock);
				if (close(sock) == -1)
					ulog(LLOG_ERROR, "Error closing fake server %s socket %d after unsuccessful bind to port %u: %s\n", t->desc->name, sock, (unsigned)port, strerror(errno));
				return false;
			}
			t->candidate = sock;
		} // Otherwise, the port is different than before, but 0 ‒ means desable this service ‒ nothing allocated
	}
	return true;
}

static void config_finish(struct context *context, bool activate) {
	struct user_data *u = context->user_data;
	for (size_t i = 0; i < u->server_count; i ++) {
		struct fd_tag *t = &u->tags[u->tag_indices[i]];
		if (activate) {
			if (t->fd != t->candidate) {
				if (t->desc->server_set_fd_cb)
					t->desc->server_set_fd_cb(context, t->server, t->candidate, t->port_candidate);
				if (t->fd) {
					loop_plugin_unregister_fd(context, t->fd);
					if (close(t->fd) == -1)
						ulog(LLOG_ERROR, "Error closing old server FD %d of %s: %s\n", t->fd, t->desc->name, strerror(errno));
				}
				t->port = t->port_candidate;
				t->fd = t->candidate;
			}
		} else if (t->candidate) {
			loop_plugin_unregister_fd(context, t->candidate);
			if (close(t->candidate) == -1)
				ulog(LLOG_ERROR, "Error closing candidate FD %d of server %s: %s\n", t->candidate, t->desc->name, strerror(errno));
		}
		t->port_candidate = 0;
		t->candidate = 0;
	}
}

#ifdef STATIC
struct plugin *plugin_info_fake(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Fake",
		.version = 1,
		.init_callback = initialize,
		.config_check_callback = config,
		.config_finish_callback = config_finish
	};
	return &plugin;
}

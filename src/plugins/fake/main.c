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

#include "main.h"
#include "server.h"
#include "log.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/loop.h"
#include "../../core/uplink.h"

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

struct fd_tag {
	const struct server_desc *desc;
	struct server_data *server;
	struct conn_data *conn;
	int fd, candidate;
	uint16_t port, port_candidate;
	bool accept_here; // When the thing is readable, call accept here instead of server_ready
	bool ignore_inactivity; // Don't close due to inactivity
	size_t server_index;
	struct sockaddr_in6 addr;
	socklen_t addr_len;
	size_t inactivity_timeout;
	bool inactivity_timeout_active;
	bool closed;
};

struct user_data {
	struct fd_tag *tags;
	size_t *tag_indices;
	size_t server_count, tag_count;
	uint32_t config_version;
	uint32_t max_age;
	bool log_credentials_candidate;
	struct log *log;
	struct mem_pool *log_pool;
};

static void connected(struct context *context) {
	uplink_plugin_send_message(context, "C", 1);
}

static void initialize(struct context *context) {
	struct user_data *u = context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	size_t server_count = 0, tag_count = 0;
	for (const struct server_desc *desc = server_descs; desc->name; desc++) {
		server_count ++;
		tag_count += 1 + desc->max_conn;
	}
	*u = (struct user_data) {
		.tags = mem_pool_alloc(context->permanent_pool, tag_count * sizeof *u->tags),
		.tag_indices = mem_pool_alloc(context->permanent_pool, (server_count + 1) * sizeof *u->tag_indices),
		.log_pool = loop_pool_create(context->loop, context, "Fake log")
	};
	u->log = log_alloc(context->permanent_pool, u->log_pool);
	memset(u->tags, 0, tag_count * sizeof * u->tags);
	size_t pos = 0, i = 0;
	for (const struct server_desc *desc = server_descs; desc->name; desc++) {
		u->tags[pos].desc = desc;
		u->tags[pos].server_index = i;
		u->tags[pos].ignore_inactivity = true;
		u->tag_indices[i ++] = pos;
		if (desc->server_alloc_cb)
			u->tags[pos].server = desc->server_alloc_cb(context, &u->tags[pos], context->permanent_pool, desc);
		if (desc->max_conn) {
			for (size_t j = pos; j < pos + 1 + desc->max_conn; j ++) {
				// The description and server are shared between all the connections
				u->tags[j].desc = desc;
				u->tags[j].server_index = u->tags[pos].server_index;
				u->tags[j].server = u->tags[pos].server;
				// But a connection structure is for each of them
				if (desc->conn_alloc_cb)
					u->tags[j].conn = desc->conn_alloc_cb(context, &u->tags[j], context->permanent_pool, u->tags[pos].server);
			}
			u->tags[pos].accept_here = true;
		} else if (desc->conn_alloc_cb)
			u->tags[pos].conn = desc->conn_alloc_cb(context, &u->tags[pos], context->permanent_pool, u->tags[pos].server);
		pos += 1 + desc->max_conn;
	}
	// Bumper
	u->tag_indices[i] = pos;
	u->server_count = server_count;
	u->tag_count = tag_count;
	// We may be initialized after connection is made, ask for config
	connected(context);
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
			int optval = 1;
			if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval) == -1) {
				ulog(LLOG_WARN, "Couldn't set the SO_REUSEADDR on fake server %s socket %d: %s, trying to continue anyway\n", t->desc->name, sock, strerror(errno));
			}
			if (bind(sock, (const struct sockaddr *)&addr, sizeof addr) == -1) {
				ulog(LLOG_ERROR, "Couldn't bind fake server %s socket %d to port %u: %s\n", t->desc->name, sock, (unsigned)port, strerror(errno));
				loop_plugin_unregister_fd(context, sock);
				if (close(sock) == -1)
					ulog(LLOG_ERROR, "Error closing fake server %s socket %d after unsuccessful bind to port %u: %s\n", t->desc->name, sock, (unsigned)port, strerror(errno));
				return false;
			}
			if (listen(sock, 20) == -1) {
				ulog(LLOG_ERROR, "Could't listen on socket %d of fake server %s: %s\n", sock, t->desc->name, strerror(errno));
				loop_plugin_unregister_fd(context, sock);
				if (close(sock) == -1)
					ulog(LLOG_ERROR, "Error closing fake server %s socket %d after unsuccessful listen: %s\n", t->desc->name, sock, strerror(errno));
				return false;
			}
			t->candidate = sock;
		} // Otherwise, the port is different than before, but 0 ‒ means desable this service ‒ nothing allocated
	}
	const struct config_node *opt = loop_plugin_option_get(context, "log_credentials");
	if (opt) {
		if (opt->value_count != 1) {
			ulog(LLOG_ERROR, "Option log_credentials must have single value, not %zu\n", opt->value_count);
			return false;
		}
		if (!opt->values[0]) {
			ulog(LLOG_ERROR, "Option log_credentials is empty\n");
			return false;
		}
		char *end;
		long p = strtol(opt->values[0], &end, 10);
		if (end && *end) {
			ulog(LLOG_ERROR, "Error parsing log_credentials, must be 0 or 1\n");
			return false;
		}
		u->log_credentials_candidate = p;
	} else {
		u->log_credentials_candidate = false;
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
					t->desc->server_set_fd_cb(context, t, t->server, t->candidate, t->port_candidate);
				if (t->fd) {
					loop_plugin_unregister_fd(context, t->fd);
					if (close(t->fd) == -1)
						ulog(LLOG_ERROR, "Error closing old server FD %d of %s: %s\n", t->fd, t->desc->name, strerror(errno));
				}
				t->port = t->port_candidate;
				t->fd = t->candidate;
			}
			log_set_send_credentials(u->log, u->log_credentials_candidate);
		} else if (t->candidate) {
			loop_plugin_unregister_fd(context, t->candidate);
			if (close(t->candidate) == -1)
				ulog(LLOG_ERROR, "Error closing candidate FD %d of server %s: %s\n", t->candidate, t->desc->name, strerror(errno));
		}
		t->port_candidate = 0;
		t->candidate = 0;
	}
}

static char *addr2str(struct mem_pool *pool, struct sockaddr *addr, socklen_t addr_len) {
	const size_t addr_max_len = 40; // 32 hex digits, 7 colons and one NULL byte
	char *result = mem_pool_alloc(pool, addr_max_len);
	const size_t port_max_len = 10;
	char *port = mem_pool_alloc(pool, port_max_len);
	int error = getnameinfo(addr, addr_len, result, addr_max_len, port, port_max_len, NI_NUMERICHOST | NI_NUMERICSERV);
	if (error) {
		ulog(LLOG_ERROR, "Error translating to address: %s\n", gai_strerror(error));
		strcpy(result, "<error>");
	}
	return mem_pool_printf(pool, "[%s]:%s", result, port);
}

static void log_send(struct context *context) {
	size_t msg_size;
	const uint8_t *msg = log_dump(context, context->user_data->log, &msg_size);
	uplink_plugin_send_message(context, msg, msg_size);
}

#define MAX_INFOS 4

static void push_info(struct event_info *infos, size_t *pos, const char *content, enum event_info_type type) {
	if (content) {
		infos[(*pos) ++] = (struct event_info) {
			.type = type,
			.content = content
		};
		assert(*pos < MAX_INFOS);
		infos[*pos].type = EI_LAST;
	}
}

static void log_wrapper(struct context *context, struct fd_tag *tag, enum event_type type, const char *reason, const char *username, const char *password) {
	ulog(LLOG_DEBUG, "Logging event %hhu for tag %p\n", (uint8_t)type, (void *)tag);
	struct user_data *u = context->user_data;
	assert(tag->addr.sin6_family == AF_INET6);
	struct event_info infos[MAX_INFOS] = { [0] = { .type = EI_LAST } };
	size_t evpos = 0;
	push_info(infos, &evpos, reason, EI_REASON);
	push_info(infos, &evpos, username, EI_NAME);
	push_info(infos, &evpos, password, EI_PASSWORD);
	if (log_event(context, u->log, tag->desc->code, tag->addr.sin6_addr.s6_addr, 16, type, infos))
		log_send(context);
}

void conn_closed(struct context *context, struct fd_tag *tag, bool error, const char *reason) {
	if (!tag->closed)
		log_wrapper(context, tag, error ? EVENT_LOST : EVENT_DISCONNECT, reason, NULL, NULL);
	tag->closed = true;
	if (tag->inactivity_timeout_active) {
		tag->inactivity_timeout_active = false;
		loop_timeout_cancel(context->loop, tag->inactivity_timeout);
	}
	loop_plugin_unregister_fd(context, tag->fd);
	if (close(tag->fd) == -1)
		ulog(LLOG_ERROR, "Failed to close FD %d of connection %p/%p of fake server %s: %s\n", tag->fd, (void *)tag->conn, (void *)tag, tag->desc->name, strerror(errno));
	tag->fd = 0;
}

void conn_log_attempt(struct context *context, struct fd_tag *tag, const char *username, const char *password) {
	ulog(LLOG_DEBUG, "Login attempt on %p from %s\n", (void *)tag, addr2str(context->temp_pool, (struct sockaddr *)&tag->addr, tag->addr_len));
	log_wrapper(context, tag, EVENT_LOGIN, NULL, username, password);
}

static void conn_inactive(struct context *context, void *data, size_t id) {
	struct fd_tag *tag = data;
	assert(tag->inactivity_timeout == id);
	ulog(LLOG_DEBUG, "Connection %p/%p with FD %d of fake server %s timed out after %u ms\n", (void *)tag->conn, (void *)tag, tag->fd, tag->desc->name, tag->desc->conn_timeout);
	tag->inactivity_timeout_active = false; // It fired, no longer active.
	log_wrapper(context, tag, EVENT_TIMEOUT, NULL, NULL, NULL);
	tag->closed = true;
	conn_closed(context, tag, false, "timeout");
}

static void activity(struct context *context, struct fd_tag *tag) {
	if (tag->ignore_inactivity)
		return;
	if (tag->inactivity_timeout_active)
		loop_timeout_cancel(context->loop, tag->inactivity_timeout);
	tag->inactivity_timeout = loop_timeout_add(context->loop, tag->desc->conn_timeout, context, tag, conn_inactive);
	tag->inactivity_timeout_active = true;
}

static void fd_ready(struct context *context, int fd, void *tag) {
	struct user_data *u = context->user_data;
	struct fd_tag *t = tag;
	if (t->accept_here) {
		size_t si = t->server_index;
		size_t ti = u->tag_indices[si], te = u->tag_indices[si+1];
		struct fd_tag *empty = NULL;
		for (size_t i = ti + 1; i < te; i ++)
			if (!u->tags[i].fd) {
				empty = &u->tags[i];
				break;
			}
		if (empty) {
			assert(empty->desc == t->desc);
			assert(empty->server == t->server);
			empty->addr_len = sizeof empty->addr;
			struct sockaddr *addr_p = (struct sockaddr *)&empty->addr;
			int new = accept(fd, addr_p, &empty->addr_len);
			if (new == -1) {
				ulog(LLOG_ERROR, "Failed to accept connection on FD %d for fake server %s: %s\n", fd, t->desc->name, strerror(errno));
			}
			loop_plugin_register_fd(context, new, empty);
			ulog(LLOG_DEBUG, "Accepted connecion %d from %s on FD %d for fake server %s\n", new, addr2str(context->temp_pool, addr_p, empty->addr_len), fd, t->desc->name);
			empty->fd = new;
			empty->closed = false;
			if (empty->desc->conn_set_fd_cb)
				empty->desc->conn_set_fd_cb(context, empty, empty->server, empty->conn, new);
			log_wrapper(context, empty, EVENT_CONNECT, NULL, NULL, NULL);
			activity(context, empty);
		} else {
			// No place to put it into.
			struct fd_tag aux_tag;
			struct sockaddr *addr_p = (struct sockaddr *)&aux_tag.addr;
			int new = accept(fd, addr_p, &aux_tag.addr_len);
			if (new == -1) {
				ulog(LLOG_ERROR, "Failed to accept extra connection on FD %d for fake server %s: %s\n", fd, t->desc->name, strerror(errno));
				return;
			}
			ulog(LLOG_WARN, "Throwing out connection %d from %s accepted on %d of fake server %s, too many opened ones\n", fd, addr2str(context->temp_pool, addr_p, aux_tag.addr_len), fd, t->desc->name);
			if (close(new) == -1) {
				ulog(LLOG_ERROR, "Error throwing newly accepted connection %d from %s accepted on %d of fake server %s: %s\n", new, addr2str(context->temp_pool, addr_p, aux_tag.addr_len), fd, t->desc->name, strerror(errno));
				return;
			}
			log_wrapper(context, &aux_tag, EVENT_CONNECT_EXTRA, NULL, NULL, NULL);
		}
	} else {
		if (t->desc->server_ready_cb)
			t->desc->server_ready_cb(context, t, t->server, t->conn);
		activity(context, t);
	}
}

struct config_packet {
	uint32_t version;
	uint32_t max_age;
	uint32_t max_size;
	uint32_t max_attempts;
} __attribute__((packed));

static void server_config(struct context *context, const uint8_t *data, size_t length) {
	const struct config_packet *config = (const struct config_packet *)data;
	if (length < sizeof *config) {
		ulog(LLOG_ERROR, "Config data too short for the Fake plugin, need %zu bytes and have only %zu\n", sizeof *config, length);
		abort();
	}
	if (length > sizeof *config)
		ulog(LLOG_ERROR, "Too much data for the Fake plugin, need only %zu bytes, but %zu arrived (ignoring for forward compatibility)\n", sizeof *config, length);
	struct user_data *u = context->user_data;
	if (u->config_version == ntohl(config->version)) {
		ulog(LLOG_DEBUG, "Not updating Fake config, version matches at %u\n", (unsigned)u->config_version);
		return;
	}
	u->config_version = ntohl(config->version);
	ulog(LLOG_INFO, "Fake configuration version %u\n", (unsigned)u->config_version);
	log_set_limits(u->log, ntohl(config->max_size), ntohl(config->max_attempts));
	u->max_age = ntohl(config->max_age);
	// TODO: Schedule the timeouts, if any
}

static void uplink_data(struct context *context, const uint8_t *data, size_t length) {
	if (!length) {
		ulog(LLOG_ERROR, "Empty message for the Fake plugin\n");
		abort();
	}
	switch (*data) {
		case 'C':
			server_config(context, data + 1, length - 1);
			break;
		default:
			ulog(LLOG_ERROR, "Invalid opcode for Fake plugin (ignorig for forward compatibility): %c\n", (char)*data);
			break;
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
		.uplink_connected_callback = connected,
		.uplink_data_callback = uplink_data,
		.config_check_callback = config,
		.config_finish_callback = config_finish,
		.fd_callback = fd_ready
	};
	return &plugin;
}

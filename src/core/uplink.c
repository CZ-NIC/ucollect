/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "uplink.h"
#include "mem_pool.h"
#include "loop.h"
#include "util.h"
#include "context.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <netdb.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <atsha204.h>
#include <time.h>
#include <stdio.h>
#include <zlib.h>

static void atsha_log_callback(const char *msg) {
	ulog(LLOG_ERROR, "ATSHA: %s\n", msg);
}

enum auth_status {
	AUTHENTICATED,
	SENT,
	NOT_STARTED,
	FAILED
};

enum rdd_status {
	RDD_END_LOOP,
	RDD_REPEAT,
	RDD_DATA
};

#define IPV6_LEN 16

struct uplink;

struct err_handler {
	struct epoll_handler handler;
	struct uplink *uplink;
	int fd;
	struct err_handler *next;
};

struct uplink {
	// Will always be uplink_read, this is to be able to use it as epoll_handler
	void (*uplink_read)(struct uplink *uplink, uint32_t events);
	struct loop *loop;
	struct mem_pool *buffer_pool;
	const char *remote_name, *service, *login, *password, *cert;
	struct addrinfo *addrinfo;
	const uint8_t *buffer;
	uint8_t *buffer_pos;
	struct err_handler *empty_handler;
	size_t buffer_size, size_rest;
	uint32_t reconnect_timeout;
	bool has_size;
	bool last_ipv6; // Was the last attempt over IPv6?
	// Timeouts for pings, etc.
	size_t ping_timeout; // The ID of the timeout.
	size_t pings_unanswered; // Number of pings sent without answer (in a row)
	bool ping_scheduled;
	bool reconnect_scheduled;
	bool seen_data;
	size_t reconnect_id; // The ID of the reconnect timeout
	int fd;
	uint64_t last_connect;
	size_t addr_len;
	uint8_t address[IPV6_LEN];
	enum auth_status auth_status;
	size_t login_failure_count;
	z_stream zstrm_send;
	z_stream zstrm_recv;
	uint8_t *inc_buffer;
	size_t inc_buffer_size;
	const char *status_file;
};

static void dump_status(struct uplink *uplink) {
	const char *status = "unknown";
	if (uplink->fd == -1) {
		status = "offline";
	} else {
		switch (uplink->auth_status) {
			case AUTHENTICATED:
				status = "online";
				break;
			case SENT:
			case NOT_STARTED:
				status = "connecting";
				break;
			case FAILED:
				status = "bad-auth";
				break;
		}
	}
	ulog(LLOG_DEBUG, "Dump status %s\n", status);
	if (!uplink->status_file)
		return;
	FILE *sf = fopen(uplink->status_file, "w");
	if (!sf) {
		ulog(LLOG_ERROR, "Couldn't dump current uplink status to file %s: %s\n", uplink->status_file, strerror(errno));
		return;
	}
	fprintf(sf, "%s\t%llu\n", status, (unsigned long long)time(NULL));
	if (fclose(sf) == EOF)
		ulog(LLOG_WARN, "Error closing status file %s/%p: %s\n", uplink->status_file, (void *)sf, strerror(errno));
}

static void uplink_disconnect(struct uplink *uplink, bool reset_reconnect);
static void connect_fail(struct uplink *uplink);

static void update_addrinfo(struct uplink *uplink) {
	if (uplink->addrinfo) {
		freeaddrinfo(uplink->addrinfo);
		uplink->addrinfo = NULL;
	}
	if (!uplink->remote_name || !uplink->service)
		return; // No info to run through.
	int result = getaddrinfo(uplink->remote_name, uplink->service, &(struct addrinfo) {
		.ai_family = AF_UNSPEC
	}, &uplink->addrinfo);
	if (result) {
		ulog(LLOG_ERROR, "Failed to resolve uplink %s:%s: %s\n", uplink->remote_name, uplink->service, gai_strerror(result));
		freeaddrinfo(uplink->addrinfo);
		uplink->addrinfo = NULL;
	}
	bool seen_v4 = false, seen_v6 = false;
	for (struct addrinfo *info = uplink->addrinfo; info; info = info->ai_next) {
		if (info->ai_family == AF_INET)
			seen_v4 = true;
		else if (info->ai_family == AF_INET6)
			seen_v6 = true;
	}
	if (!seen_v4)
		ulog(LLOG_WARN, "Didn't get any V4 address in resolution of %s\n", uplink->remote_name);
	if (!seen_v6)
		ulog(LLOG_WARN, "Didn't get any V6 address in resolution of %s\n", uplink->remote_name);
}

static void err_read(void *data, uint32_t unused) {
	(void) unused;
	struct err_handler *handler = data;
	if (handler->fd == -1) {
		/*
		 * This is some kind of strange race condition. Unfortunately,
		 * it could lead to producing a large amount of error messages
		 * here, spamming the log. It usually gets fixed soon by itself.
		 * So we just sleep a little while to give it time. This is a
		 * hack, but no idea how to solve that :-(.
		 */
		ulog(LLOG_WARN, "Received stray read on socat error socket\n");
		uplink_disconnect(handler->uplink, true);
		connect_fail(handler->uplink);
		nanosleep(&(struct timespec) {
			.tv_sec = STRAY_READ_SLEEP / 1000,
			.tv_nsec = 1000000 * (STRAY_READ_SLEEP % 1000)
		}, NULL);
		return;
	}
#define bufsize 1024
	char buffer[bufsize + 1];
	ssize_t result = recv(handler->fd, buffer, bufsize, MSG_DONTWAIT);
	switch (result) {
		case -1:
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return; // This is OK
			} else {
				ulog(LLOG_ERROR, "Error reading errors from socat: %s\n", strerror(errno));
				// Fall through to close
			}
		case 0:
			loop_unregister_fd(handler->uplink->loop, handler->fd);
			close(handler->fd);
			handler->fd = -1;
			handler->next = handler->uplink->empty_handler;
			handler->uplink->empty_handler = handler;
			break;
		default: {
			char *pos = buffer;
			buffer[result] = '\0';
			// Split to lines, skip empty ones and print the stuff
			while (pos && *pos) {
				char *end = index(pos, '\n');
				if (end)
					*end = '\0';
				if (*(pos + 1))
					ulog(LLOG_ERROR, "Error from socat: %s\n", pos);
				pos = end;
				if (pos)
					pos ++;
			}
			break;
		}
	}
}

static bool uplink_connect_internal(struct uplink *uplink) {
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
		ulog(LLOG_ERROR, "Couldn't create socket pair: %s\n", strerror(errno));
		return false;
	}
	int errs[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, errs) == -1) {
		close(sockets[0]);
		close(sockets[1]);
		ulog(LLOG_ERROR, "Couldn't create error sockets: %s\n", strerror(errno));
		return false;
	}
	pid_t socat = loop_fork(uplink->loop);
	if (socat == -1) {
		close(sockets[0]);
		close(sockets[1]);
		close(errs[0]);
		close(errs[1]);
		ulog(LLOG_ERROR, "Can't fork: %s\n", strerror(errno));
		return false;
	}
	uplink->last_ipv6 = !uplink->last_ipv6;
	if (socat) {
		close(sockets[1]);
		close(errs[1]);
		uplink->fd = sockets[0];
		uplink->auth_status = NOT_STARTED;
		struct err_handler *handler = uplink->empty_handler;
		if (handler) {
			uplink->empty_handler = handler->next;
		} else {
			handler = mem_pool_alloc(loop_permanent_pool(uplink->loop), sizeof *handler);
		}
		*handler = (struct err_handler) {
			.handler = {
				.handler = err_read
			},
			.fd = errs[0],
			.uplink = uplink
		};
		loop_register_fd(uplink->loop, errs[0], &handler->handler);
		ulog(LLOG_INFO, "Socat started\n");
		dump_status(uplink);
		return true;
	} else {
		close(sockets[0]);
		close(errs[0]);
		if (dup2(sockets[1], 0) == -1 || dup2(sockets[1], 1) == -1 || dup2(errs[1], 2) == -1) {
			ulog(LLOG_ERROR, "Couldn't dup: %s\n", strerror(errno));
			exit(1);
		}
		close(sockets[1]);
		close(errs[1]);
		/*
		 * Explanation of the last_ipv6:
		 * Socat won't, unfortunately, try both IPv4 and IPv6 if both are
		 * available. So it goes for IPv4 or IPv6 ‒ but whatever we chose
		 * might be the wrong choice. So we keep switching from one to
		 * another on each connection attempt. If only one is available,
		 * every other connection attempt will fail, but that's acceptable.
		 * We could do something more clever, but this is simple and works.
		 * See ticket #3106.
		 */
		const char *remote = mem_pool_printf(loop_temp_pool(uplink->loop), "OPENSSL:%s:%s,cafile=%s,cipher=HIGH:!LOW:!MEDIUM:!SSLv2:!aNULL:!eNULL:!DES:!3DES:!AES128:!CAMELLIA128,method=TLS1.2,pf=ip%d", uplink->remote_name, uplink->service, uplink->cert, uplink->last_ipv6 ? 6 : 4);
		ulog(LLOG_DEBUG, "Starting socat with %s\n", remote);
		execlp("socat", "socat", "STDIO", remote, (char *) NULL);
		die("Exec should never have exited but it did: %s\n", strerror(errno));
	}
}

static void send_ping(struct context *context, void *data, size_t id);

// Connect to remote. Blocking.
static void uplink_connect(struct uplink *uplink) {
	assert(uplink->fd == -1);
	if (uplink->last_connect + RECONN_TIME > loop_now(uplink->loop)) {
		ulog(LLOG_WARN, "Reconnecting too often, waiting a little while\n");
		connect_fail(uplink);
		return;
	}
	if (uplink->login_failure_count ++ >= LOGIN_FAILURE_LIMIT)
		die("Too many login failures, giving up\n");
	uplink->last_connect = loop_now(uplink->loop);
	bool connected = uplink_connect_internal(uplink);
	if (!connected) {
		ulog(LLOG_ERROR, "Failed to connect to any address and port for uplink %s:%s\n", uplink->remote_name, uplink->service);
		connect_fail(uplink);
		return;
	}
	// We connected. Reset the reconnect timeout.
	if (uplink->seen_data)
		uplink->reconnect_timeout = 0;
	uplink->seen_data = false;
	// Reset the pings.
	uplink->pings_unanswered = 0;
	uplink->ping_timeout = loop_timeout_add(uplink->loop, PING_TIMEOUT, NULL, uplink, send_ping);
	uplink->ping_scheduled = true;
	loop_register_fd(uplink->loop, uplink->fd, (struct epoll_handler *) uplink);
	update_addrinfo(uplink);
	deflateReset(&(uplink->zstrm_send));
	inflateReset(&(uplink->zstrm_recv));
}

static void reconnect_now(struct context *unused, void *data, size_t id_unused) {
	struct uplink *uplink = data;
	(void) unused;
	(void) id_unused;
	ulog(LLOG_INFO, "Reconnecting to %s:%s now\n", uplink->remote_name, uplink->service);
	uplink->reconnect_scheduled = false;
	uplink_connect(uplink);
}

static void connect_fail(struct uplink *uplink) {
	assert(!uplink->reconnect_scheduled);
	if (uplink->auth_status == FAILED) {
		uplink->auth_status = NOT_STARTED;
		uplink->reconnect_timeout = RECONNECT_AUTH;
	} else if (uplink->reconnect_timeout) {
		// Some subsequent reconnect.
		uplink->reconnect_timeout *= RECONNECT_MULTIPLY;
		if (uplink->reconnect_timeout > RECONNECT_MAX)
			uplink->reconnect_timeout = RECONNECT_MAX;
	} else
		uplink->reconnect_timeout = RECONNECT_BASE;
	ulog(LLOG_INFO, "Going to reconnect to %s:%s after %d seconds\n", uplink->remote_name, uplink->service, uplink->reconnect_timeout / 1000);
	uplink->reconnect_id = loop_timeout_add(uplink->loop, uplink->reconnect_timeout, NULL, uplink, reconnect_now);
	uplink->reconnect_scheduled = true;
}

static void buffer_reset(struct uplink *uplink) {
	uplink->buffer_size = uplink->size_rest = 0;
	uplink->buffer = uplink->buffer_pos = NULL;
	uplink->has_size = false;
	mem_pool_reset(uplink->buffer_pool);
}

static void uplink_disconnect(struct uplink *uplink, bool reset_reconnect) {
	if (uplink->reconnect_scheduled && reset_reconnect) {
		loop_timeout_cancel(uplink->loop, uplink->reconnect_id);
		uplink->reconnect_scheduled = false;
	}
	if (uplink->fd != -1) {
		ulog(LLOG_DEBUG, "Closing uplink connection %d to %s:%s\n", uplink->fd, uplink->remote_name, uplink->service);
		loop_uplink_disconnected(uplink->loop);
		loop_unregister_fd(uplink->loop, uplink->fd);
		int result = close(uplink->fd);
		if (result != 0)
			ulog(LLOG_ERROR, "Couldn't close uplink connection to %s:%s, leaking file descriptor %d (%s)\n", uplink->remote_name, uplink->service, uplink->fd, strerror(errno));
		uplink->fd = -1;
		buffer_reset(uplink);
		if (uplink->ping_scheduled)
			loop_timeout_cancel(uplink->loop, uplink->ping_timeout);
		uplink->ping_scheduled = false;
		uplink->addr_len = 0;
	} else
		ulog(LLOG_DEBUG, "Uplink connection to %s:%s not open\n", uplink->remote_name, uplink->service);
	dump_status(uplink);
}

static void send_ping(struct context *context_unused, void *data, size_t id_unused) {
	(void) context_unused;
	(void) id_unused;
	struct uplink *uplink = data;
	uplink->ping_scheduled = false;
	// How long does it not answer pings?
	if (uplink->pings_unanswered >= PING_COUNT) {
		ulog(LLOG_ERROR, "Too many pings not answered on %s:%s, reconnecting\n", uplink->remote_name, uplink->service);
		// Let the connect be called from the loop, so it works even if uplink_disconnect makes a plugin crash
		uplink_reconnect(uplink);
		uplink->pings_unanswered = 0;
		return;
	}
	ulog(LLOG_DEBUG, "Sending ping to %s:%s\n", uplink->remote_name, uplink->service);
	uplink->pings_unanswered ++;
	uplink_send_message(uplink, 'P', NULL, 0);
	// Schedule new ping
	uplink->ping_timeout = loop_timeout_add(uplink->loop, PING_TIMEOUT, NULL, uplink, send_ping);
	uplink->ping_scheduled = true;
}

char *uplink_parse_string(struct mem_pool *pool, const uint8_t **buffer, size_t *length) {
	size_t len_size = sizeof(uint32_t);
	if (*length < len_size) {
		return NULL;
	}
	uint32_t len;
	memcpy(&len, *buffer, sizeof len);
	len = ntohl(len);
	if (*length < len + len_size) {
		return NULL;
	}
	char *result = mem_pool_alloc(pool, len + 1);
	memcpy(result, *buffer + len_size, len);
	result[len] = '\0';
	*length -= len_size + len;
	*buffer += len_size + len;
	return result;
}

uint32_t uplink_parse_uint32(const uint8_t **buffer, size_t *length) {
	uint32_t result;
	uplink_parse(buffer, length, "u", &result, "Anonymous uint32_t");
	return result;
}

void uplink_parse(const uint8_t **buffer, size_t *length, const char *format, ...) {
	va_list args;
	va_start(args, format);
	for (const char *command = format; *command; command ++) {
		switch (*command) {
			case 's': {
				ulog(LLOG_DEBUG_VERBOSE, "Going to parse uplink string\n");
				char **result = va_arg(args, char **);
				sanity(result, "Need string result\n");
				size_t *str_length = va_arg(args, size_t *);
				struct mem_pool *pool = va_arg(args, struct mem_pool *);
				sanity(pool, "Need memory pool\n");
				const char *message = va_arg(args, const char *);
				uint32_t len_wire;
				sanity(*length >= sizeof len_wire, "Reading uplink string length failed, with only %zu bytes available: %s\n", *length, message);
				memcpy(&len_wire, *buffer, sizeof len_wire);
				*length -= sizeof len_wire;
				*buffer += sizeof len_wire;
				len_wire = ntohl(len_wire);
				if (str_length)
					*str_length = len_wire;
				sanity(*length >= len_wire, "Reading uplink string failed, with only %zu bytes available, but %zu needed: %s\n", *length, (size_t)len_wire, message);
				*result = mem_pool_alloc(pool, len_wire + 1);
				memcpy(*result, *buffer, len_wire);
				*length -= len_wire;
				*buffer += len_wire;
				(*result)[len_wire] = '\0';
				break;
			}
			case 'u': {
				ulog(LLOG_DEBUG_VERBOSE, "Going to parse uint32_t\n");
				uint32_t *result = va_arg(args, uint32_t *);
				sanity(result, "Need uint32_t result\n");
				const char *message = va_arg(args, const char *);
				sanity(*length >= sizeof *result, "Reading uint32_t failed, only %zu bytes available: %s\n", *length, message);
				memcpy(result, *buffer, sizeof *result);
				*length -= sizeof *result;
				*buffer += sizeof *result;
				*result = ntohl(*result);
				break;
			}
			case 'b': {
				ulog(LLOG_DEBUG_VERBOSE, "Going to parse bool\n");
				bool *result = va_arg(args, bool *);
				sanity(result, "Need bool result\n");
				sanity(sizeof *result == 1, "Confused. Bool should have size 1, not %zu\n", sizeof *result);
				const char *message = va_arg(args, const char *);
				sanity(*length, "Reading bool failed, no data available: %s\n", message);
				*result = **buffer;
				(*buffer) ++;
				(*length) --;
				break;
			}
			case 'c': {
				ulog(LLOG_DEBUG_VERBOSE, "Going to parse char\n");
				char *result = va_arg(args, char *);
				sanity(result, "Need char result\n");
				sanity(sizeof *result == 1, "Confused. Char should have size 1, not %zu\n", sizeof *result);
				const char *message = va_arg(args, const char *);
				sanity(*length, "Reading char failed, no data available: %s\n", message);
				*result = **buffer;
				(*buffer) ++;
				(*length) --;
				break;
			}
			default:
				insane("Passed invalid uplink_parse type %c\n", *command);
		}
	}
	va_end(args);
}

static void v_uplink_render(uint8_t **buffer, size_t *length, const char *format, va_list args) {
	for (const char *command = format; *command; command ++) {
		switch (*command) {
			case 's': {
				ulog(LLOG_DEBUG_VERBOSE, "Going to encode uplink string\n");
				const char *s = va_arg(args, const char *);
				size_t len = va_arg(args, size_t);
				uint32_t len_encoded = htonl(len);
				sanity(*length >= sizeof len_encoded, "Not enough space to encode string length, only %zu bytes available.\n", *length);
				memcpy(*buffer, &len_encoded, sizeof len_encoded);
				*buffer += sizeof len_encoded;
				*length -= sizeof len_encoded;
				sanity(*length >= len, "Not enough space to encode string data, only %zu bytes available.\n", *length);
				memcpy(*buffer, s, len);
				*buffer += len;
				*length -= len;
				break;
			}
			case 'u': {
				ulog(LLOG_DEBUG_VERBOSE, "Going to encode uplink uint32_t\n");
				uint32_t u = va_arg(args, uint32_t);
				sanity(*length >= sizeof u, "Not enough space to encode uint32_t, only %zu bytes available.\n", *length);
				u = htonl(u);
				memcpy(*buffer, &u, sizeof u);
				*buffer += sizeof u;
				*length -= sizeof u;
				break;
			}
			case 'b':
			case 'c': {
				const char *name = *command == 'b' ? "bool" : "char";
				ulog(LLOG_DEBUG_VERBOSE, "Going to encode %s\n", name);
				char val = va_arg(args, int); // Variadic functions store small values as ints
				sanity(*length, "Not enough space to encode %s.\n", name);
				**buffer = val;
				(*buffer) ++;
				(*length) --;
				break;
			}
			default:
				insane("Passed invalid uplink_render type %c\n", *command);
		};
	}
}

void uplink_render(uint8_t **buffer, size_t *length, const char *format, ...) {
	va_list args;
	va_start(args, format);
	v_uplink_render(buffer, length, format, args);
	va_end(args);
}

uint8_t *uplink_render_alloc(size_t *length, size_t extra_space, struct mem_pool *pool, const char *format, ...) {
	// First compute the needed space
	size_t l = extra_space;
	va_list args;
	va_start(args, format);
	for (const char *command = format; *command; command ++) {
		switch (*command) {
			case 's':
				va_arg(args, const char *); // The buffer itself
				l += va_arg(args, size_t) + sizeof(uint32_t);
				break;
			case 'u':
				va_arg(args, uint32_t);
				l += sizeof(uint32_t);
				break;
			case 'b':
			case 'c':
				va_arg(args, int); // These are converted to int by the variadic functions
				l ++;
				break;
			default:
				insane("Unknown storage size of uplink type %c\n", *command);
		}
	}
	va_end(args);
	// Allocate the space
	uint8_t *result = mem_pool_alloc(pool, l), *buffer = result;
	*length = l;
	// Render into the buffer
	va_start(args, format);
	v_uplink_render(&buffer, &l, format, args);
	sanity(l == extra_space, "Extra space doesn't match in upling_render_alloc with format %s: %zu vs %zu\n", format, l, extra_space);
	sanity(buffer = result + *length - l, "Buffer position doesn't match in uplink_render_alloc with format %s\n", format);
	va_end(args);
	return result;
}

void uplink_render_string(const void *string, uint32_t length, uint8_t **buffer_pos, size_t *buffer_len) {
	uplink_render(buffer_pos, buffer_len, "s", string, length);
}

void uplink_render_uint32(uint32_t value, uint8_t **buffer_pos, size_t *buffer_len) {
	uplink_render(buffer_pos, buffer_len, "u", value);
}

static void handle_activation(struct uplink *uplink) {
	const uint8_t *buffer = uplink->buffer;
	size_t rest = uplink->buffer_size;
	struct mem_pool *temp_pool = loop_temp_pool(uplink->loop);
	uint32_t amount = uplink_parse_uint32(&buffer, &rest);
	if (amount == 0) {
		ulog(LLOG_WARN, "Empty activation message. Why?\n");
		return;
	}
	struct plugin_activation *plugins = mem_pool_alloc(temp_pool, amount * sizeof *plugins);
	for (size_t i = 0; i < amount; i ++) {
		if (!(plugins[i].name = uplink_parse_string(temp_pool, &buffer, &rest)))
			die("The activation plugin name broken\n");
		if (rest <= sizeof plugins[i].hash) // One more for the activation flag
			die("Activation message buffer too short to read plugin hash and bool (%zu available)\n", rest);
		memcpy(plugins[i].hash, buffer, sizeof plugins[i].hash);
		buffer += sizeof plugins[i].hash;
		rest -= sizeof plugins[i].hash;
		plugins[i].activate = (*buffer == 'A');
		buffer ++;
		rest --;
	}
	if (rest != 0) {
		ulog(LLOG_WARN, "Extra %zu bytes in activation message, ignoring\n", rest);
	}
	/*
	 * Reset the buffer and clean up before calling the loop.
	 * It may contain callbacks to the plugins. If they contained an error,
	 * They are handled by a longjump directly to the loop, so the end of the
	 * function might not be called.
	 */
	buffer_reset(uplink);
	loop_plugin_activation(uplink->loop, plugins, amount);
}

static void handle_buffer(struct uplink *uplink) {
	if (uplink->has_size) {
		// If we already have the size, it is the real message
		ulog(LLOG_DEBUG, "Uplink %s:%s received complete message of %zu bytes\n", uplink->remote_name, uplink->service, uplink->buffer_size);

		if (uplink->buffer_size) {
			char command = *uplink->buffer ++;
			uplink->buffer_size --;
			struct mem_pool *temp_pool = loop_temp_pool(uplink->loop);
			if (uplink->auth_status == AUTHENTICATED || uplink->auth_status == SENT) {
				switch (command) {
					case 'R': { // Route data to given plugin
						uplink->login_failure_count = 0; // If we got data, we know the login was successful
						const char *plugin_name = uplink_parse_string(temp_pool, &uplink->buffer, &uplink->buffer_size);
						if (!plugin_name)
							die("Plugin name broken in route message\n");
						/*
						 * The loop_plugin_send_data contains call to plugin callback.
						 * Such callback can fail and we would like to recover. That is done
						 * by a longjump directly to the loop. That'd mean this function is not
						 * completed, therefore we make sure it works well even in such case -
						 * we create a copy of the buffer and then reset the buffer before
						 * going to the plugin (resetting it again below doesn't hurt anything).
						 */
						uint8_t *buffer = mem_pool_alloc(temp_pool, uplink->buffer_size);
						memcpy(buffer, uplink->buffer, uplink->buffer_size);
						size_t length = uplink->buffer_size;
						buffer_reset(uplink);
						if (loop_plugin_send_data(uplink->loop, plugin_name, buffer, length)) {
							dump_status(uplink);
						} else {
							ulog(LLOG_ERROR, "Plugin %s referenced by uplink does not exist\n", plugin_name);
							// TODO: Create some function for formatting messages
							size_t pname_len = strlen(plugin_name);
							// 1 for 'P', 1 for '\0' at the end
							size_t msgsize = 1 + sizeof pname_len + pname_len;
							char buffer[msgsize];
							// First goes error specifier - 'P'lugin name doesn't exist
							buffer[0] = 'P';
							// Then one byte after, the length of the name
							uint32_t len_n = htonl(pname_len);
							memcpy(buffer + 1, &len_n, sizeof len_n);
							// And the string itself
							memcpy(buffer + 1 + sizeof len_n, plugin_name, pname_len);
							// Send an error
							uplink_send_message(uplink, 'E', buffer, msgsize);
						}
						break;
					}
					case 'P': // Ping from the server. Send a pong back.
						  uplink_send_message(uplink, 'p', uplink->buffer, uplink->buffer_size);
						  dump_status(uplink);
						  break;
					case 'p': // Pong. Reset the number of unanswered pings, we got some answer, the link works
						  uplink->pings_unanswered = 0;
						  break;
					case 'F':
						  ulog(LLOG_ERROR, "Server rejected our authentication\n");
						  // Schedule another attempt in 10 minutes
						  uplink_disconnect(uplink, true);
						  uplink->auth_status = FAILED;
						  dump_status(uplink);
						  connect_fail(uplink);
						  break;
					case 'A':
						handle_activation(uplink);
						break;
					default:
						  ulog(LLOG_ERROR, "Received unknown command %c from uplink %s:%s\n", command, uplink->remote_name, uplink->service);
						  break;
				}
				if (uplink->auth_status == SENT)
					uplink->auth_status = AUTHENTICATED; // We are authenticated if the server writes to us
			} else {
				if (command == 'C' && uplink->auth_status == NOT_STARTED) {
					// The server is sending a challenge.
					// We send a „sesssion ID“ ‒ our PID. This way, the server will know if it's the same process reconnecting and drop the old connection sooner.
					ulog(LLOG_DEBUG, "Sending session ID\n");
					uint32_t sid = htonl(getpid());
					uplink_send_message(uplink, 'S', &sid, sizeof sid);
					ulog(LLOG_DEBUG, "Sending login info\n");
					// Prepare data
#define HALF_SIZE 16
					atsha_big_int server_challenge, client_response;
					uint8_t local_half[HALF_SIZE] = PASSWD_HALF;
					sanity(HALF_SIZE + uplink->buffer_size == sizeof(server_challenge.data), "Wrong length of server challenge, givint up\n");
					server_challenge.bytes = HALF_SIZE + uplink->buffer_size;
					memcpy(server_challenge.data, local_half, HALF_SIZE);
					memcpy(server_challenge.data + HALF_SIZE, uplink->buffer, uplink->buffer_size);
					// Get the chip handle
					atsha_set_log_callback(atsha_log_callback);
					struct atsha_handle *cryptochip = atsha_open();
					if (!cryptochip)
						die("Couldn't open the ATSHA204 chip\n");
					// Read the serial number
					atsha_big_int serial;
					int result = atsha_serial_number(cryptochip, &serial);
					if (result != ATSHA_ERR_OK)
						die("Don't known my own name: %s\n", atsha_error_name(result));

					// Compute response to the server challenge
					result = atsha_challenge_response(cryptochip, server_challenge, &client_response);
					if (result != ATSHA_ERR_OK)
						die("Can't answer challenge: %s\n", atsha_error_name(result));
					// Close the chip (and unlock)
					atsha_close(cryptochip);

					// Send all computed stuff
					size_t len = 1 + 2*sizeof(uint32_t) + serial.bytes + client_response.bytes;
					uint8_t *message = mem_pool_alloc(temp_pool, len);
					message[0] = 'O';
					uint8_t *message_pos = message + 1;
					size_t len_pos = len - 1;
					uplink_render_string(serial.data, serial.bytes, &message_pos, &len_pos);
					uplink_render_string(client_response.data, client_response.bytes, &message_pos, &len_pos);
					assert(!len_pos);
					uplink_send_message(uplink, 'L', message, len);
					/*
					 * Send 'H'ello. For now, it is empty. In future, we expect to have program & protocol version,
					 * list of plugins and possibly other things too.
					 */
					uplink->auth_status = SENT;
					uint8_t proto_version = PROTOCOL_VERSION;
					uplink_send_message(uplink, 'H', &proto_version, sizeof proto_version);
					loop_uplink_connected(uplink->loop);
				} else
					// This is an insult, and we won't talk to the other side any more!
					ulog(LLOG_ERROR, "Protocol violation at login\n");
			}
		} else {
			ulog(LLOG_ERROR, "Received an empty message from %s:%s\n", uplink->remote_name, uplink->service);
		}

		// Next time start a new message from scratch
		buffer_reset(uplink);
	} else {
		// This is the size of the real message. Get the buffer for the message.
		uint32_t buffer_size;
		memcpy(&buffer_size, uplink->buffer, sizeof buffer_size);
		uplink->buffer_size = uplink->size_rest = ntohl(buffer_size);
		uplink->buffer = uplink->buffer_pos = mem_pool_alloc(uplink->buffer_pool, uplink->buffer_size);
		uplink->has_size = true;
	}
}

static enum rdd_status read_decompressed_data(struct uplink *uplink, ssize_t *available_output) {
	// Update stream's output buffer according to uplink "request"
	uplink->zstrm_recv.avail_out = (unsigned int)uplink->size_rest;
	uplink->zstrm_recv.next_out = (unsigned char *)uplink->buffer_pos;

	// Try to read from buffers, they can have some data
	int ret = inflate(&(uplink->zstrm_recv), Z_SYNC_FLUSH);
	if (ret == Z_DATA_ERROR) {
		ulog(LLOG_ERROR, "Data for decompression are corrupted. Reconnecting.");
		// Data corrupted. Reconnect.
		uplink_reconnect(uplink);
		return RDD_END_LOOP;
	}
	*available_output = uplink->size_rest - uplink->zstrm_recv.avail_out;

	// There was some data in deflate or receive buffer
	if (*available_output != 0) {
		return RDD_DATA;
	}

	// Read is requested and there are no more received data
	// So, try to read something
	if (uplink->zstrm_recv.avail_in == 0) {
		ssize_t amount = recv(uplink->fd, uplink->inc_buffer, uplink->inc_buffer_size, MSG_DONTWAIT);
		if (amount == -1) {
			switch (errno) {
				/*
				 * Non-fatal errors. EINTR can happen without problems.
				 *
				 * EAGAIN/EWOULDBLOCK should not, but it is said linux can create spurious
				 * events on sockets sometime.
				 */
				case EAGAIN:
#if EAGAIN != EWOULDBLOCK
				case EWOULDBLOCK:
#endif
					return RDD_END_LOOP;
				case EINTR:
					ulog(LLOG_WARN, "Non-fatal error reading from %s:%s (%d): %s\n", uplink->remote_name, uplink->service, uplink->fd, strerror(errno));
					return RDD_REPEAT; // We'll just retry next time
				case ECONNRESET:
					// This is similar to close
					ulog(LLOG_WARN, "Connection to %s:%s reset, reconnecting\n", uplink->remote_name, uplink->service);
					goto CLOSED;
				default: // Other errors are fatal, as we don't know the cause
					die("Error reading from uplink %s:%s (%s)\n", uplink->remote_name, uplink->service, strerror(errno));
			}
		} else if (amount == 0) { // 0 means socket closed
			ulog(LLOG_WARN, "Remote closed the uplink %s:%s, reconnecting\n", uplink->remote_name, uplink->service);
CLOSED:
			assert(!uplink->reconnect_scheduled);
			uplink->reconnect_id = loop_timeout_add(uplink->loop, uplink->reconnect_timeout / 1000, NULL, uplink, reconnect_now);
			uplink->reconnect_scheduled = true;
			uplink_disconnect(uplink, false);
			return RDD_END_LOOP; // We are done with this socket.
		} else {
			// Some data was read, so update input buffer for stream
			uplink->zstrm_recv.avail_in = (unsigned int)amount;
			uplink->zstrm_recv.next_in = (unsigned char *)uplink->inc_buffer;

			if (MAX_LOG_LEVEL == LLOG_DEBUG_VERBOSE) {

				ulog(LLOG_DEBUG_VERBOSE, "compression: recv: compressed data (size %zu): %s\n", amount, mem_pool_hex(loop_temp_pool(uplink->loop), uplink->inc_buffer, amount));
			}
		}
	}

	// First time had inflate empty buffer - try it again after read
	ret = inflate(&(uplink->zstrm_recv), Z_SYNC_FLUSH);
	if (ret == Z_DATA_ERROR) {
		ulog(LLOG_ERROR, "Data for decompression are corrupted. Reconnecting.");
		// Data corrupted. Reconnect.
		uplink_reconnect(uplink);
		return RDD_END_LOOP;
	}
	*available_output = uplink->size_rest - uplink->zstrm_recv.avail_out;

	if (*available_output == 0) {
		// The same case as EAGAIN;
		return RDD_END_LOOP;
	}

	return RDD_DATA;
}

static void uplink_read(struct uplink *uplink, uint32_t unused) {
	(void) unused;
	ulog(LLOG_DEBUG, "Read on uplink %s:%s (%d)\n", uplink->remote_name, uplink->service, uplink->fd);
	if (uplink->fd == -1) {
		ulog(LLOG_WARN, "Spurious read on uplink\n");
		return;
	}
	size_t limit = 50; // Max of 50 messages, so we don't block forever. Arbitrary smallish number.
	while (limit) {
		limit --;
		if (!uplink->buffer) {
			// No buffer - prepare one for the size
			uplink->buffer_size = uplink->size_rest = sizeof(uint32_t);
			uplink->buffer = uplink->buffer_pos = mem_pool_alloc(uplink->buffer_pool, uplink->buffer_size);
		}

		ssize_t amount = 0;
		enum rdd_status ret = read_decompressed_data(uplink, &amount);
		if (ret == RDD_END_LOOP) {
			return;

		} else if (ret == RDD_REPEAT) {
			continue;

		} else {
			if (MAX_LOG_LEVEL == LLOG_DEBUG_VERBOSE) {
				ulog(LLOG_DEBUG_VERBOSE, "compression: recv: original data (size %zu): %s\n", amount, mem_pool_hex(loop_temp_pool(uplink->loop), uplink->buffer_pos, amount));
			}
			uplink->seen_data = true;
			uplink->buffer_pos += amount;
			uplink->size_rest -= amount;
			if (uplink->size_rest == 0) {
				handle_buffer(uplink);
				if (uplink->fd == -1)
					break; // The connection got closed in handle_buffer
			}
		}
	}
}

struct uplink *uplink_create(struct loop *loop) {
	ulog(LLOG_INFO, "Creating uplink\n");
	struct mem_pool *permanent_pool = loop_permanent_pool(loop);
	struct uplink *result = mem_pool_alloc(permanent_pool, sizeof *result);
	unsigned char *incoming_buffer = mem_pool_alloc(permanent_pool, COMPRESSION_BUFFSIZE);
	*result = (struct uplink) {
		.uplink_read = uplink_read,
		.loop = loop,
		.buffer_pool = loop_pool_create(loop, NULL, mem_pool_printf(loop_temp_pool(loop), "Buffer pool for uplink")),
		.fd = -1,
		.inc_buffer = incoming_buffer,
		.inc_buffer_size = COMPRESSION_BUFFSIZE

	};
        result->zstrm_send.zalloc = Z_NULL;
        result->zstrm_send.zfree = Z_NULL;
        result->zstrm_send.opaque = Z_NULL;
        if (deflateInit(&(result->zstrm_send), COMPRESSION_LEVEL) != Z_OK)
		die("Could not initialize zlib (compression stream)\n");
        result->zstrm_recv.zalloc = Z_NULL;
        result->zstrm_recv.zfree = Z_NULL;
        result->zstrm_recv.opaque = Z_NULL;
        result->zstrm_recv.avail_in = 0;
	if (inflateInit(&(result->zstrm_recv)) != Z_OK)
		die("Could not initialize zlib (decompression stream)\n");
	loop_uplink_set(loop, result);
	return result;
}

void uplink_set_status_file(struct uplink *uplink, const char *file) {
	assert(!uplink->status_file);
	uplink->status_file = file;
	dump_status(uplink);
}

void uplink_reconnect(struct uplink *uplink) {
	// Reconnect
	if (!uplink->reconnect_scheduled) {
		uplink->reconnect_id = loop_timeout_add(uplink->loop, 0, NULL, uplink, reconnect_now);
		uplink->reconnect_scheduled = true;
	}
	uplink_disconnect(uplink, false);
}

void uplink_configure(struct uplink *uplink, const char *remote_name, const char *service, const char *login, const char *password, const char *cert) {
	bool same =
		uplink->remote_name && strcmp(uplink->remote_name, remote_name) == 0 &&
		uplink->service && strcmp(uplink->service, service) == 0 &&
		uplink->cert && strcmp(uplink->cert, cert) == 0 &&
		(uplink->login == login || (uplink->login && strcmp(uplink->login, login) == 0)) &&
		(uplink->password == password || (uplink->password && strcmp(uplink->password, password)) == 0);
	// Set the new remote endpoint
	uplink->remote_name = remote_name;
	uplink->service = service;
	uplink->login = login;
	uplink->password = password;
	uplink->cert = cert;
	// If it is the same, we don't need to reconnect (but we need to store the new pointers, the old might die soon)
	if (same) {
		ulog(LLOG_DEBUG, "Not changing remote uplink as it is the same\n");
		return;
	}
	ulog(LLOG_INFO, "Changing remote uplink address to %s:%s\n", remote_name, service);
	uplink_reconnect(uplink);
	update_addrinfo(uplink);
}

void uplink_destroy(struct uplink *uplink) {
	ulog(LLOG_INFO, "Destroying uplink to %s:%s\n", uplink->remote_name, uplink->service);
	// The memory pools get destroyed by the loop, we just close the socket, if any.
	uplink_disconnect(uplink, true);
	// And destroy library handlers
	deflateEnd(&(uplink->zstrm_send));
	inflateEnd(&(uplink->zstrm_recv));
	if (uplink->status_file)
		if (unlink(uplink->status_file) == -1)
			ulog(LLOG_ERROR, "Couldn't remove status file %s: %s\n", uplink->status_file, strerror(errno));
}

static bool send_raw_data(struct uplink *uplink, const uint8_t *buffer, size_t size, int flags) {
	// Compression don't produce output every time.
	// Do not try to send empty data, this case is not rare .
	if (size == 0)
		return true;
	if (MAX_LOG_LEVEL == LLOG_DEBUG_VERBOSE) {
		ulog(LLOG_DEBUG_VERBOSE, "compression: send: compressed data (size %zu, %s): %s\n", size, (flags == 0) ? "LAST" : "MSG_MORE", mem_pool_hex(loop_temp_pool(uplink->loop), buffer, size));
	}
	while (size > 0) {
		ssize_t amount = send(uplink->fd, buffer, size, MSG_NOSIGNAL | flags);
		if (amount == -1) {
			switch (errno) {
				case EINTR:
					// Just interrupt called during send. Retry.
					ulog(LLOG_WARN, "EINTR during send to %s:%s\n", uplink->remote_name, uplink->service);
					continue;
				case ECONNRESET:
				case EPIPE:
					// Lost connection. Reconnect.
					uplink_reconnect(uplink);
					return false;
				default:
					// Fatal errors
					die("Error sending to %s:%s\n", uplink->remote_name, uplink->service);
			}
		} else {
			buffer += amount;
			size -= amount;
		}
	}
	return true;
}

static bool buffer_send(struct uplink *uplink, const uint8_t *buffer, size_t size, int flags) {
	size_t buffsize = COMPRESSION_BUFFSIZE;
	struct mem_pool *temp_pool = loop_temp_pool(uplink->loop);
	uint8_t *output_buffer = mem_pool_alloc(temp_pool, buffsize);
	uplink->zstrm_send.avail_in = size;
	uplink->zstrm_send.next_in = (unsigned char *)buffer;

	if (MAX_LOG_LEVEL == LLOG_DEBUG_VERBOSE) {
		ulog(LLOG_DEBUG_VERBOSE, "compression: send: original data (size %zu, %s): %s\n", size, (flags == 0) ? "LAST" : "MSG_MORE", mem_pool_hex(loop_temp_pool(uplink->loop), buffer, size));
	}
	unsigned int available_output = 0;
	while (uplink->zstrm_send.avail_in > 0) {
		uplink->zstrm_send.avail_out = buffsize;
		uplink->zstrm_send.next_out = output_buffer;
		deflate(&(uplink->zstrm_send), Z_NO_FLUSH);
		available_output = buffsize - uplink->zstrm_send.avail_out;
		if (available_output == 0) {
			ulog(LLOG_DEBUG_VERBOSE, "compression: no output data prepared after deflate call\n");
		}
		if (!send_raw_data(uplink, output_buffer, available_output, MSG_MORE)) {
			return false;
		}
	}
	if (flags == 0) { // No more data, flush the rest of compressed message and sent it.
		ulog(LLOG_DEBUG_VERBOSE, "compression: start sync flushing\n");
		do {
			uplink->zstrm_send.avail_out = buffsize;
			uplink->zstrm_send.next_out = output_buffer;
			deflate(&(uplink->zstrm_send), Z_SYNC_FLUSH);
			available_output = buffsize - uplink->zstrm_send.avail_out;
			if (available_output == 0) {
				ulog(LLOG_DEBUG_VERBOSE, "compression: no output data prepared after deflate call (SYNC)\n");
			}
			int finish_flag = (uplink->zstrm_send.avail_out == 0) ? MSG_MORE : 0;
			if (!send_raw_data(uplink, output_buffer, available_output, finish_flag)) {
				return false;
			}
		} while (uplink->zstrm_send.avail_out == 0);
	}
	ulog(LLOG_DEBUG_VERBOSE, "compression: return\n");
	return true;
}

bool uplink_send_message(struct uplink *uplink, char type, const void *data, size_t size) {
	if (uplink->fd == -1)
		return false; // Not connected, we can't send.
	// The +1 is for the type sent directly after the length
	size_t head_len = sizeof(uint32_t) + 1;
	uint8_t head_buffer[head_len];
	uint32_t head_size = htonl(size + 1);
	memcpy(head_buffer, &head_size, sizeof head_size);
	head_buffer[head_len - 1] = type;
	return buffer_send(uplink, head_buffer, head_len, MSG_MORE) && buffer_send(uplink, data, size, 0);
}

bool uplink_plugin_send_message(struct context *context, const void *data, size_t size) {
	if (!loop_plugin_active(context))
		return false;
	const char *name = loop_plugin_get_name(context);
	ulog(LLOG_DEBUG, "Sending message of size %zu from plugin %s\n", size, name);
	uint32_t name_length = strlen(name);
	uint32_t length = sizeof name_length + name_length + size;
	uint8_t *buffer = mem_pool_alloc(context->temp_pool, length);
	uint8_t *buffer_pos = buffer;
	size_t buffer_len = length;
	uplink_render_string(name, name_length, &buffer_pos, &buffer_len);
	memcpy(buffer_pos, data, size);
	return uplink_send_message(context->uplink, 'R', buffer, length);
}

void uplink_realloc_config(struct uplink *uplink, struct mem_pool *pool) {
	if (uplink->remote_name)
		uplink->remote_name = mem_pool_strdup(pool, uplink->remote_name);
	if (uplink->service)
		uplink->service = mem_pool_strdup(pool, uplink->service);
	if (uplink->login)
		uplink->login = mem_pool_strdup(pool, uplink->login);
	if (uplink->password)
		uplink->password = mem_pool_strdup(pool, uplink->password);
	if (uplink->cert)
		uplink->cert = mem_pool_strdup(pool, uplink->cert);
}

struct addrinfo *uplink_addrinfo(struct uplink *uplink) {
	return uplink->addrinfo;
}

void uplink_close(struct uplink *uplink) {
	if (uplink->fd != -1)
		close(uplink->fd);
}

bool uplink_connected(const struct uplink *uplink) {
	return uplink && uplink->fd != -1 && uplink->auth_status == AUTHENTICATED;
}

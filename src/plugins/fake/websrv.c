/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2016 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "websrv.h"
#include "main.h"

#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/context.h"

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#define LINE_MAX 512

struct conn_data {
	int fd;
	char line_data[LINE_MAX];
	char *line;
	char *close_reason;
	struct fd_tag *tag;
};

struct conn_data *http_conn_alloc(struct context *context __attribute__((unused)), struct fd_tag *tag, struct mem_pool *pool, struct server_data *server __attribute__((unused))) {
	struct conn_data *result = mem_pool_alloc(pool, sizeof *result);
	ulog(LLOG_DEBUG, "Allocated http connection %p for tag %p\n", (void *)result, (void *)tag);
	memset(result, 0, sizeof *result);
	return result;
}

static void line_reset(struct conn_data *conn) {
	conn->line = conn->line_data;
}

void http_conn_set_fd(struct context *context __attribute__((unused)), struct fd_tag *tag, struct server_data *server __attribute__((unused)), struct conn_data *conn, int fd) {
	conn->fd = fd;
	ulog(LLOG_DEBUG, "Accepted http connection %p on tag %p, fd %d\n", (void *)conn, (void *)tag, fd);
	conn->tag = tag;
	line_reset(conn);
}

static void do_close(struct context *context, struct conn_data *conn, bool error) {
	conn_closed(context, conn->tag, error, conn->close_reason);
}

static bool line_handle(struct conn_data *data) {
	// TODO: Implement. The real fun goes here.
	return true;
}

static bool char_handle(struct context *context __attribute__((unused)), struct fd_tag *tag __attribute__((unused)), struct conn_data *conn, uint8_t ch) {
	switch (ch) {
		case '\r':
			// We simply ignore CR and wait for LF (we don't validate they go after each other)
			break;
		case '\n':
			// LF came ‒ handle the whole accumulated line
			return line_handle(conn);
		default:
			// Just accumulate the data of the line
			if (conn->line && conn->line - conn->line_data + 1 < LINE_MAX)
				*(conn->line ++) = ch;
			break;
	}
	return true;
}

void http_data(struct context *context, struct fd_tag *tag, struct server_data *server __attribute__((unused)), struct conn_data *conn) {
	const size_t block = 1024;
	void *buffer = mem_pool_alloc(context->temp_pool, block);
	ssize_t amount = recv(conn->fd, buffer, block, MSG_DONTWAIT);
	bool error = false;
	switch (amount) {
		case -1: // Error
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				// Try again (we'll be called by the main loop)
				return;
			ulog(LLOG_DEBUG, "Error on http connection %p on tag %p with fd %d: %s\n", (void *)conn, (void *)tag, conn->fd, strerror(errno));
			conn->close_reason = strerror(errno);
			error = true;
			// No break - fall through
		case 0: // Close
			ulog(LLOG_DEBUG, "Closed http connection %p/%p/%d\n", (void *)conn, (void *)tag, conn->fd);
			if (!conn->close_reason)
				conn->close_reason = "Closed";
			do_close(context, conn, error);
			return;
		default:
			break;
	}
	// OK, we have data, all unusual cases handled above
	ulog(LLOG_DEBUG, "Http data on connection %p/%p/%d: %s\n", (void *)conn, (void *)tag, conn->fd, mem_pool_hex(context->temp_pool, buffer, amount));
	const uint8_t *data = buffer;
	for (ssize_t i = 0; i < amount; i ++)
		if (!char_handle(context, tag, conn, data[i])) {
			do_close(context, conn, false);
			return;
		}
}

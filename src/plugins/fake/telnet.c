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

#include "telnet.h"
#include "main.h"

#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/context.h"

#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

struct conn_data {
	int fd; // Just so it's not empty. It'll be replaced by real data later on.
};

struct conn_data *telnet_conn_alloc(struct context *context, struct fd_tag *tag, struct mem_pool *pool, struct server_data *server) {
	(void)context;
	(void)server;
	struct conn_data *result = mem_pool_alloc(pool, sizeof *result);
	ulog(LLOG_DEBUG, "Allocated telnet connection %p for tag %p\n", (void *)result, (void *)tag);
	memset(result, 0, sizeof *result);
	return result;
}

void telnet_conn_set_fd(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn, int fd) {
	(void)context;
	(void)server;
	// TODO: Reset the internal data structures in conn once there's something inside
	conn->fd = fd;
	ulog(LLOG_DEBUG, "Accepted to telnet connection %p on tag %p, fd %d\n", (void *)conn, (void *)tag, fd);
}

void telnet_data(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn) {
	(void)server;
	const size_t block = 1024;
	void *buffer = mem_pool_alloc(context->temp_pool, block);
	ssize_t amount = recv(conn->fd, buffer, block, MSG_DONTWAIT);
	bool error = false;
	switch (amount) {
		case -1: // Error
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				return;
			ulog(LLOG_DEBUG, "Error on telnet connection %p on tag %p with fd %d: %s\n", (void *)conn, (void *)tag, conn->fd, strerror(errno));
			error = true;
			// No break - fall through
		case 0: // Close
			ulog(LLOG_DEBUG, "Closed telnet connection %p/%p/%d\n", (void *)conn, (void *)tag, conn->fd);
			conn_closed(context, tag, error);
			return;
		default:
			break;
	}
	// OK, we have data, all unusual cases handled above
	// TODO: Parse what is inside
	ulog(LLOG_DEBUG, "Telnet data on connection %p/%p/%d: %s\n", (void *)conn, (void *)tag, conn->fd, mem_pool_hex(context->temp_pool, buffer, amount));
}

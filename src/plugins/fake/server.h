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

#ifndef UCOLLECT_FAKE_SERVER_H
#define UCOLLECT_FAKE_SERVER_H

#include <stdint.h>

struct server_data;
struct server_desc;
struct conn_data;
struct context;
struct mem_pool;
struct fd_tag;

typedef struct server_data *(*server_alloc)(struct context *context, struct fd_tag *tag, struct mem_pool *pool, const struct server_desc *desc);
typedef void (*server_set_fd)(struct context *context, struct fd_tag *tag, struct server_data *server, int fd, uint16_t port);
typedef struct conn_data *(*conn_alloc)(struct context *context, struct fd_tag *tag, struct mem_pool *pool, struct server_data *server);
// Also accept...
typedef void (*conn_set_fd)(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn, int fd);
typedef void (*server_ready)(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn);

/*
 * There are two modes in which this may operate. A connected mode and unconnected one.
 *
 * In the connected mode, certain number of simultaneous connections can be accepted
 * (specifid by max_conn). A main FD is allocated in the beginning and set with
 * server_set_fd. Bunch of conn structures is allocated and whenever new connection
 * is accepted, the conn_set_fd is called on one of the conn structures with the new
 * fd. The server_ready is called on it every time data is available.
 *
 * In the unconnected mode, single conn structure is allocated, the main FD is set into
 * it and then the server_ready is called with it whenever it is readable. This mode
 * is enabled by setting max_conn to 0. The conn_set_fd callback is never used here.
 *
 * Note that even the main FD can change during the lifetime of the server.
 *
 * Only the server_ready is mandatory.
 */
struct server_desc {
	const char *name;
	int sock_type; // like SOCK_STREAM or SOCK_DGRAM
	uint16_t default_port;
	server_alloc server_alloc_cb;
	server_set_fd server_set_fd_cb;
	conn_alloc conn_alloc_cb;
	conn_set_fd conn_set_fd_cb;
	server_ready server_ready_cb;
	unsigned max_conn; // Maximum number of parallel connections. If more are to be opened, new ones are immediatelly closed after accepting.
	unsigned conn_timeout; // Timeout in milliseconds ‒ if nothing comes over the socket in this time, it is dropped
};

extern const struct server_desc *server_descs;

#endif

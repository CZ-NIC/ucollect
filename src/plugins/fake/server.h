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

struct server_data;
struct server_desc;
struct conn_data;
struct context;

typedef struct server_data *(*server_init)(struct context *context, struct server_desc *desc, int fd);
typedef void (*server_teardown)(struct context *context, struct server_data *data);
typedef struct conn_data *(*server_accept)(struct context *context, struct server_data *data, int new_fd);
typedef void (*conn_teardown)(struct context *context, struct server_data *data, struct conn_data *conn);
typedef void (*server_ready)(struct context *context, struct server_data *data, struct conn_data *conn);

struct server_desc {
	const char *name;
	int sock_type; // like SOCK_STREAM or SOCK_DGRAM
	server_init init_cb;
	server_teardown teardown_cb;
	// If the callback is set, it'll automatically accept new connections, up to some limit
	server_accept accept_cb;
	conn_teardown close_cb;
	// Called when the file descriptor is ready (either accepted one if accept_cb is set, or the global one, if accept_cb is not set).
	server_ready ready_cb;
	unsigned max_conn; // Maximum number of parallel connections. If more are to be opened, new ones are immediatelly closed after accepting.
	unsigned conn_timeout; // Timeout in milliseconds
};

const struct server_desc *server_descs;

#endif

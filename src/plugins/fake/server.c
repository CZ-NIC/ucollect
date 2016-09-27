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

#include "telnet.h"
#include "websrv.h"

#include <stdlib.h>
#include <sys/socket.h>

#define SECOND (1000)

const struct server_desc server_descs_intern[] = {
	{
		.name = "telnet",
		.code = 'T',
		.sock_type = SOCK_STREAM,
		.default_port = 23,
		// No server-scope data, so skip server_alloc and server_set_fd
		.conn_alloc_cb = telnet_conn_alloc,
		.conn_set_fd_cb = telnet_conn_set_fd,
		.server_ready_cb = telnet_data,
		.max_conn = 20,
		.conn_timeout = 30 * SECOND
	},
	{	// An alternative telnet port
		.name = "telnet_alt",
		.code = 't',
		.sock_type = SOCK_STREAM,
		.default_port = 2323,
		.conn_alloc_cb = telnet_conn_alloc,
		.conn_set_fd_cb = telnet_conn_set_fd,
		.server_ready_cb = telnet_data,
		.max_conn = 20,
		.conn_timeout = 30 * SECOND
	},
	{
		.name = "http",
		.code = 'H',
		.sock_type = SOCK_STREAM,
		.default_port = 80,
		// No server-scope data, so skip server_alloc and server_set_fd
		.conn_alloc_cb = http_conn_alloc,
		.conn_set_fd_cb = http_conn_set_fd,
		.server_ready_cb = http_data,
		.max_conn = 20,
		.conn_timeout = 30 * SECOND
	},
	{
		.name = NULL
	}
};

const struct server_desc *server_descs = server_descs_intern;

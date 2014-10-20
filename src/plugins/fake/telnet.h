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

#ifndef UCOLLECT_FAKE_TELNET_H
#define UCOLLECT_FAKE_TELNET_H

struct context;
struct mem_pool;

struct server_data; // Not used here at all. No need to coordinate through central data structure
struct conn_data;
struct fd_tag;

struct conn_data *telnet_conn_alloc(struct context *context, struct fd_tag *tag, struct mem_pool *pool, struct server_data *server);
void telnet_conn_set_fd(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn, int fd);
void telnet_data(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn);

#endif

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

#ifndef UCOLLECT_TELNET_MAIN_H
#define UCOLLECT_TELNET_MAIN_H

#include <stdbool.h>

struct context *context;
struct fd_tag *tag;

/*
 * Report that the connection was closed by either side.
 *
 * The error indicates if it was in some error (no matter what) or
 * if it was clean shutdown.
 */
void conn_closed(struct context *context, struct fd_tag *tag, bool error);
/*
 * Log that the other side attemted connection.
 */
void conn_log_attempt(struct context *context, struct fd_tag *tag);

#endif

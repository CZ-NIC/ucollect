/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#ifndef UCOLLECT_CONTEXT_H
#define UCOLLECT_CONTEXT_H

// Forward declarations
struct mem_pool;
struct loop;
/*
 * This is not a true forward declaration. This is not defined in this library at all.
 * We expect each plugin defines its own version. This is slightly better than
 * plain type casting, as the compiler does some minimal checks about type safety
 * inside the same plugin.
 */
struct user_data;

struct context {
	struct mem_pool *permanent_pool;
	struct mem_pool *temp_pool;
	struct loop *loop;
	struct uplink *uplink;
	struct user_data *user_data;
};

#endif

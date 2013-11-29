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

#ifndef UCOLLECT_BUCKETS_CRITERIA_H
#define UCOLLECT_BUCKETS_CRITERIA_H

#include <stddef.h>
#include <stdint.h>

struct mem_pool;
struct packet_info;

struct criterion_def {
	size_t key_size;
	/*
	 * A function to extract the key that we hash by. The packet is already
	 * the one to examine (so the caller shall traverse the list of next
	 * pointers in case of tunnels are used.
	 *
	 * It shall return either NULL, in case the packet doesn't contain
	 * corresponding key (eg. it is of different protocol), or a pointer
	 * to key_size bytes of the key. If the key is variable length,
	 * the whole length of key_size must be allocated and padded with
	 * constant values (zeroes, for example).
	 *
	 * The data may reside directly in the packet, or they can be allocated
	 * from the pool.
	 */
	const uint8_t *(*extract_key)(const struct packet_info *packet, struct mem_pool *tmp_pool);
	char name; // Name as denoted in the config
};

extern struct criterion_def criteria[];

#endif

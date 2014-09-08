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

#ifndef UCOLLECT_FLOW_FLOW_H
#define UCOLLECT_FLOW_FLOW_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct packet_info;
struct mem_pool;

enum flow_ipv {
	FLOW_V4 = 0,
	FLOW_V6 = 1
};

enum flow_proto {
	FLOW_TCP = 0,
	FLOW_UDP = 2// Maybe others?
};

static const uint8_t const flow_starts[2] = { 4, 8 };

typedef uint8_t flow_addr_t[16];

// Order is in, out, resp local/remote
struct flow  {
	uint32_t count[2];
	uint64_t size[2];
	uint64_t first_time[2], last_time[2];
	uint16_t ports[2];
	flow_addr_t addrs[2];
	enum flow_ipv ipv;
	enum flow_proto proto;
	// Detected an initialization of the communication. Curretly, this is done only for TCP and it means a packet with only SYN was seen.
	bool seen_flow_start[2];
};

void flow_parse(struct flow *target, const struct packet_info *packet) __attribute__((nonnull));
size_t flow_size(const struct flow *flow) __attribute__((nonnull));
void flow_render(uint8_t *dst, size_t dst_size, const struct flow *flow) __attribute__((nonnull));
uint8_t *flow_key(const struct packet_info *packet, size_t *size, struct mem_pool *pool) __attribute__((nonnull, malloc));

#endif

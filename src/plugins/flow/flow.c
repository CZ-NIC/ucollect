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

#include "flow.h"

#include "../../core/packet.h"
#include "../../core/mem_pool.h"
#include "../../core/util.h"

#include <string.h>
#include <arpa/inet.h>

void flow_parse(struct flow *target, const struct packet_info *packet) {
	enum endpoint local = local_endpoint(packet->direction);
	enum endpoint remote = remote_endpoint(packet->direction);
	*target = (struct flow) {
		.ports = { packet->ports[local], packet->ports[remote] },
		.ipv = packet->ip_protocol == 4 ? FLOW_V4 : FLOW_V6,
		.proto = packet->app_protocol == 'T' ? FLOW_TCP : FLOW_UDP
	};
	memcpy(target->addrs[0], packet->addresses[local], packet->addr_len);
	memcpy(target->addrs[1], packet->addresses[remote], packet->addr_len);
}

uint8_t *flow_key(const struct packet_info *packet, size_t *size, struct mem_pool *pool) {
	size_t addr_s = packet->ip_protocol == 4 ? 4 : 16;
	sanity(addr_s == packet->addr_len, "Packet address length doesn't match its protocol: %zu/%c\n", addr_s, packet->ip_protocol);
	sanity(packet->direction < DIR_UNKNOWN, "Packet of unknown direction\n");
	size_t s = 2 + 2 * sizeof(uint16_t) + 2 * addr_s;
	uint8_t *result = mem_pool_alloc(pool, s);
	uint8_t *pos = result;
	*pos ++ = (uint8_t)packet->ip_protocol;
	*pos ++ = (uint8_t)packet->app_protocol;

	enum endpoint local = local_endpoint(packet->direction);
	enum endpoint remote = remote_endpoint(packet->direction);
	memcpy(pos, packet->addresses[local], addr_s);
	pos += addr_s;
	memcpy(pos, packet->addresses[remote], addr_s);
	pos += addr_s;
	memcpy(pos, &packet->ports[local], sizeof(uint16_t));
	pos += sizeof(uint16_t);
	memcpy(pos, &packet->ports[remote], sizeof(uint16_t));
	pos += sizeof(uint16_t);
	*size = s;
	return result;
}

// Encoding:
// flags (1 byte), count (2*32 bit), size (2*64 bit), ports (2*16 bit), times (4 * 64bit), addresses (either 2*32 bit or 2*128bit).
size_t flow_size(const struct flow *flow) {
	size_t size = 1 + 2 * sizeof(uint32_t) + 2 * sizeof(uint64_t) + 2* sizeof(uint16_t) + 4 * sizeof(uint64_t);
	if (flow->ipv == FLOW_V4)
		size += 2 * sizeof(uint32_t);
	else
		size += 2 * 16;
	return size;
}

void flow_render(uint8_t *dst, size_t dst_size, const struct flow *flow) {
	// Size check
	size_t size = flow_size(flow);
	sanity(dst_size == size, "Flow buffer of wrong length: %zu/%zu\n", size, dst_size);
	*dst = flow->ipv | flow->proto;
	for (size_t i = 0; i < 2; i ++)
		if (flow->seen_flow_start[i])
			*dst |= flow_starts[i];
	dst ++;
	// Encode counts
	for (size_t i = 0; i < 2; i ++) {
		uint32_t cnt = htonl(flow->count[i]);
		memcpy(dst, &cnt, sizeof cnt);
		dst += sizeof cnt;
	}
	// Encode sizes
	for (size_t i = 0; i < 2; i ++) {
		uint64_t sz = htobe64(flow->size[i]);
		memcpy(dst, &sz, sizeof sz);
		dst += sizeof sz;
	}
	// Ports
	for (size_t i = 0; i < 2; i ++) {
		uint16_t port = htons(flow->ports[i]);
		memcpy(dst, &port, sizeof port);
		dst += sizeof port;
	}
	// The four times
	uint64_t times[] = { flow->first_time[0], flow->first_time[1], flow->last_time[0], flow->last_time[1] };
	for (size_t i = 0; i < 4 ; i++) {
		uint64_t time = htobe64(times[i]);
		memcpy(dst, &time, sizeof time);
		dst += sizeof time;
	}
	size_t addr_size = flow->ipv == FLOW_V4 ? 4 : 16;
	for (size_t i = 0; i < 2; i ++) {
		memcpy(dst, flow->addrs[i], addr_size);
		dst += addr_size;
	}
}

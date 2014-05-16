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

#include "criteria.h"

#include "../../core/packet.h"
#include "../../core/mem_pool.h"

#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

// IPv6 is 16 bytes long, preceded by the version byte. We pad v4 by zeroes.
#define ADDR_SIZE 17
#define PORT_SIZE sizeof(uint16_t)

static bool copy_ip(uint8_t *where, const struct packet_info *packet) {
	enum endpoint remote = remote_endpoint(packet->direction);
	if (remote == END_COUNT)
		return false; // Strange packet, not going in or out.
	if (!packet->addresses[remote])
		return false; // Not an IP packet.
	size_t len = packet->addr_len;
	assert(ADDR_SIZE - 1 >= len);
	memcpy(where + 1, packet->addresses[remote], len);
	memset(where + 1 + len, 0, ADDR_SIZE - 1 - len);
	*where = packet->ip_protocol;
	return true;
}

static const uint8_t *extract_ip_address(const struct packet_info *packet, struct mem_pool *tmp_pool) {
	uint8_t *result = mem_pool_alloc(tmp_pool, ADDR_SIZE);
	if (!copy_ip(result, packet))
		return NULL;
	return result;
}

static bool copy_port(uint8_t *where, const struct packet_info *packet, enum endpoint which) {
	if (which == END_COUNT)
		return false;
	if (packet->ports[which] == 0)
		return false;
	uint16_t port_net = htons(packet->ports[which]);
	memcpy(where, &port_net, sizeof port_net);
	return true;
}

static const uint8_t *extract_port(const struct packet_info *packet, struct mem_pool *tmp_pool) {
	uint8_t *result = mem_pool_alloc(tmp_pool, PORT_SIZE);
	if (copy_port(result, packet, remote_endpoint(packet->direction)))
		return result;
	else
		return NULL;
}

static const uint8_t *extract_both(const struct packet_info *packet, struct mem_pool *tmp_pool) {
	uint8_t *result = mem_pool_alloc(tmp_pool, PORT_SIZE + ADDR_SIZE);
	if (copy_port(result, packet, remote_endpoint(packet->direction)) && copy_ip(result + PORT_SIZE, packet))
		return result;
	else
		return NULL;
}

static const uint8_t *extract_lport_addr(const struct packet_info *packet, struct mem_pool *tmp_pool) {
	uint8_t *result = mem_pool_alloc(tmp_pool, PORT_SIZE + ADDR_SIZE);
	if (copy_port(result, packet, local_endpoint(packet->direction)) && copy_ip(result + PORT_SIZE, packet))
		return result;
	else
		return NULL;
}

#define OUT(NAME) \
static const uint8_t *NAME##_out(const struct packet_info *packet, struct mem_pool *tmp_pool) { \
	if (packet->direction == DIR_OUT) \
		return NAME(packet, tmp_pool); \
	else \
		return NULL; \
}
OUT(extract_ip_address)
OUT(extract_port)
OUT(extract_both)
OUT(extract_lport_addr)

struct criterion_def criteria[] = {
	{ // Remote address
		.key_size = ADDR_SIZE,
		.name = 'I',
		.extract_key = extract_ip_address
	},
	{ // Remote port
		.key_size = PORT_SIZE,
		.name = 'P',
		.extract_key = extract_port
	},
	{ // Both port and address
		.key_size = PORT_SIZE + ADDR_SIZE,
		.name = 'B',
		.extract_key = extract_both
	},
	{ // Local port and remote address
		.key_size = PORT_SIZE + ADDR_SIZE,
		.name = 'L',
		.extract_key = extract_lport_addr
	},
	// The same ones, but only outgoing packets
	{ // Remote address
		.key_size = ADDR_SIZE,
		.name = 'i',
		.extract_key = extract_ip_address_out
	},
	{ // Remote port
		.key_size = PORT_SIZE,
		.name = 'p',
		.extract_key = extract_port_out
	},
	{ // Both port and address
		.key_size = PORT_SIZE + ADDR_SIZE,
		.name = 'b',
		.extract_key = extract_both_out
	},
	{ // Local port and remote address
		.key_size = PORT_SIZE + ADDR_SIZE,
		.name = 'l',
		.extract_key = extract_lport_addr_out
	},
	{ // Sentinel
		.name = '\0'
	}
};

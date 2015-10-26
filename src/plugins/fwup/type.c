/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "type.h"

#include "../../core/util.h"
#include "../../core/mem_pool.h"

#include <string.h>
#include <arpa/inet.h>

static const char *inet2str(const uint8_t *addr, size_t len, struct mem_pool *pool) {
	sanity(len == 4, "Inet address of size %zu\n", len);
	struct in_addr addr_str;
	sanity(sizeof addr_str == 4, "Wrong size of struct in_addr (%zu)\n", sizeof addr_str);
	memcpy(&addr_str.s_addr, addr, len);
	const char *result = inet_ntop(AF_INET, &addr_str, mem_pool_alloc(pool, INET_ADDRSTRLEN), INET_ADDRSTRLEN);
	// The mem_pool_hex is misuse of the memory pool, but it happens only when we are about to crash the plugin
	sanity(result, "Couldn't convert address %s to string\n", mem_pool_hex(pool, addr, len));
	return result;
}

static const char *inet62str(const uint8_t *addr, size_t len, struct mem_pool *pool) {
	sanity(len == 16, "Inet6 address of size %zu\n", len);
	struct in6_addr addr_str;
	sanity(sizeof addr_str == 16, "Wrong size of struct in6_addr (%zu)\n", sizeof addr_str);
	memcpy(&addr_str.s6_addr, addr, len);
	const char *result = inet_ntop(AF_INET6, &addr_str, mem_pool_alloc(pool, INET6_ADDRSTRLEN), INET6_ADDRSTRLEN);
	// The mem_pool_hex is misuse of the memory pool, but it happens only when we are about to crash the plugin
	sanity(result, "Couldn't convert address %s to string\n", mem_pool_hex(pool, addr, len));
	return result;
}

static const char *inetup2str(const uint8_t *addr, size_t len, size_t alen, const char *name, struct mem_pool *pool, addr2str_t sub) {
	sanity(len == alen + 2, "%s address and port of size %zu\n", name, len);
	const char *addrs = sub(addr, alen, pool);
	uint16_t port;
	// Copy out first, we worry about alignment of the data.
	memcpy(&port, addr + alen, 2);
	port = ntohs(port);
	return mem_pool_printf(pool, "%s,XXX:%u", addrs, port);
}

static const char *inetp2str(const uint8_t *addr, size_t len, struct mem_pool *pool) {
	return inetup2str(addr, len, 4, "Inet", pool, inet2str);
}

static const char *inet6p2str(const uint8_t *addr, size_t len, struct mem_pool *pool) {
	return inetup2str(addr, len, 16, "Inet6", pool, inet62str);
}

const struct set_type set_types[256] = {
	['i'] = {
		.desc = "hash:ip",
		.family = "inet",
		.addr2str = inet2str
	},
	['I'] = {
		.desc = "hash:ip",
		.family = "inet6",
		.addr2str = inet62str
	},
	['b'] = {
		.desc = "hash:ip,port",
		.family = "inet",
		.addr2str = inetp2str
	},
	['B'] = {
		.desc = "hash:ip,port",
		.family = "inet6",
		.addr2str = inet6p2str
	}
};

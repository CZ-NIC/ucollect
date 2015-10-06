/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "filter.h"

#define PLUGLIB_DO_IMPORT PLUGLIB_FUNCTIONS
#include "../../libs/diffstore/diff_store.h"

#include "../../core/trie.h"
#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

typedef bool (*filter_fun)(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet);
struct filter_type;
typedef void (*filter_parser)(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size);

struct filter_type {
	filter_fun function;
	filter_parser parser;
	uint8_t code;
};

struct filter {
	filter_fun function;
	size_t sub_count;
	struct filter *subfilters;
	struct trie *trie;
	const struct filter_type *type;
	// Info for differential plugins
	struct diff_addr_store *diff_addr_store;
	const uint8_t *address, *mask; // For range filters
	bool v6;
};

static bool filter_true(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	(void)tmp_pool;
	(void)filter;
	(void)packet;
	return true;
}

static bool filter_false(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	(void)tmp_pool;
	(void)filter;
	(void)packet;
	return false;
}

static bool filter_not(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	const struct filter *sub = filter->subfilters;
	return !sub->function(tmp_pool, sub, packet);
}

static bool filter_and(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	for (size_t i = 0; i < filter->sub_count; i ++)
		if (!filter->subfilters[i].function(tmp_pool, &filter->subfilters[i], packet))
			return false;
	return true;
}

static bool filter_or(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	for (size_t i = 0; i < filter->sub_count; i ++)
		if (filter->subfilters[i].function(tmp_pool, &filter->subfilters[i], packet))
			return true;
	return false;
}

static bool filter_value_match(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	(void)tmp_pool;
	const uint8_t *data;
	size_t size;
	assert(packet->layer == 'I'); // Checked by the caller
	assert(packet->direction < DIR_UNKNOWN);
	enum endpoint local = local_endpoint(packet->direction), remote = remote_endpoint(packet->direction);
	// Decide which part of packet we match
	switch (filter->type->code) {
		case 'p':
			data = (const uint8_t *)&packet->ports[local];
			size = 2;
			break;
		case 'P':
			data = (const uint8_t *)&packet->ports[remote];
			size = 2;
			break;
		case 'i':
			data = packet->addresses[local];
			size = packet->addr_len;
			break;
		case 'I':
			data = packet->addresses[remote];
			size = packet->addr_len;
			break;
		default:
			assert(0);
			return false;
	}
	// Look if this one is one of the matched
	return trie_lookup(filter->trie, data, size);
}

static bool filter_differential(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	enum endpoint endpoint = filter->type->code == 'd' ? local_endpoint(packet->direction) : remote_endpoint(packet->direction);
	if (endpoint == END_COUNT)
		return false; // No packets with unknown direction pass the filter
	// Check for IP address match first
	if (trie_lookup(filter->diff_addr_store->trie, packet->addresses[endpoint], packet->addr_len))
		return true;
	// We now abuse the fact that IP addresses have either 4 or 16 bytes. If it has 6 or 18, it can't be IP only, it must be IP + port
	uint8_t *compound = mem_pool_alloc(tmp_pool, packet->addr_len + sizeof(uint16_t));
	memcpy(compound, packet->addresses[endpoint], packet->addr_len);
	uint16_t port_net = htons(packet->ports[endpoint]);
	memcpy(compound + packet->addr_len, &port_net, sizeof port_net);
	return trie_lookup(filter->diff_addr_store->trie, compound, packet->addr_len + sizeof port_net);
}

static bool filter_range(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	enum endpoint endpoint = filter->type->code == 'r' ? local_endpoint(packet->direction) : remote_endpoint(packet->direction);
	if (endpoint == END_COUNT)
		return false;
	if ((filter->v6 && packet->ip_protocol != 6) || (!filter->v6 && packet->ip_protocol != 4))
		return false;
	size_t addr_len = filter->v6 ? 16 : 4;
	assert(packet->addr_len == addr_len);
	if (MAX_LOG_LEVEL >= LLOG_DEBUG_VERBOSE)
		ulog(LLOG_DEBUG_VERBOSE, "Comparing address %s with %s/%s\n", mem_pool_hex(tmp_pool, packet->addresses[endpoint], addr_len), mem_pool_hex(tmp_pool, filter->address, addr_len), mem_pool_hex(tmp_pool, filter->mask, addr_len));
	// Examine the address in 4-byte blocks
	const uint32_t *addr = (const uint32_t *)packet->addresses[endpoint];
	const uint32_t *expected = (const uint32_t *)filter->address;
	const uint32_t *mask = (const uint32_t *)filter->mask;
	addr_len /= 4;
	for (size_t i = 0; i < addr_len; i ++) {
		uint32_t masked = *(addr + i) & *(mask + i);
		if (masked != *(expected + i))
			return false;
	}
	return true;
}

static void parse_one(struct mem_pool *pool, struct filter *dest, const uint8_t **desc, size_t *size);

static void parse_sub(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size) {
	(void)type;
	struct filter *sub = mem_pool_alloc(pool, sizeof *sub);
	dest->subfilters = sub;
	dest->sub_count = 1;
	parse_one(pool, sub, desc, size);
}

static void parse_many_subs(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size) {
	uint32_t sub_count;
	sanity(*size >= sizeof sub_count, "Short data for number of subfilters for %c\n", type->code);
	memcpy(&sub_count, *desc, sizeof sub_count);
	(*desc) += sizeof sub_count;
	(*size) -= sizeof sub_count;
	sub_count = ntohl(sub_count);
	dest->sub_count = sub_count;
	struct filter *subs = mem_pool_alloc(pool, sub_count * sizeof *subs);
	dest->subfilters = subs;
	for (size_t i = 0; i < sub_count; i ++)
		parse_one(pool, &subs[i], desc, size);
}

struct trie_data {
	int dummy; // Just to prevent warning about empty struct
};

static struct trie_data mark; // To have a valid pointer to something, not used by itself

static void parse_ip_match(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size) {
	uint32_t ip_count;
	sanity(*size >= sizeof ip_count, "Short data for number of IP addresses in %c filter, only %zu available\n", type->code, *size);
	memcpy(&ip_count, *desc, sizeof ip_count);
	(*desc) += sizeof ip_count;
	(*size) -= sizeof ip_count;
	ip_count = ntohl(ip_count);
	dest->trie = trie_alloc(pool);
	for (size_t i = 0; i < ip_count; i ++) {
		sanity(*size, "Short data for IP address size in %c filter at IP #%zu\n", type->code, i);
		uint8_t ip_size = **desc;
		(*desc) ++;
		(*size) --;
		sanity(*size >= ip_size, "Short data for IP address in %c filter at IP %zu (available %zu, need %hhu)\n", type->code, i, *size, ip_size);
		*trie_index(dest->trie, *desc, ip_size) = &mark;
		(*desc) += ip_size;
		(*size) -= ip_size;
	}
}

static void parse_port_match(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size) {
	uint16_t port_count; // Only 16 bit, there can't be more than that much different ports anyway O:-)
	sanity(*size >= sizeof port_count, "Short data for number of ports in %c filter, only %zu available\n", type->code, *size);
	memcpy(&port_count, *desc, sizeof port_count);
	(*desc) += sizeof port_count;
	(*size) -= sizeof port_count;
	port_count = ntohs(port_count);
	dest->trie = trie_alloc(pool);
	for (size_t i = 0; i < port_count; i ++) {
		uint16_t port;
		sanity(*size >= sizeof port, "Short data for port in %c filter at port #%zu, only %zu available\n", type->code, i, *size);
		memcpy(&port, *desc, sizeof port);
		(*desc) += sizeof port;
		(*size) -= sizeof port;
		*trie_index(dest->trie, (const uint8_t *)&port, sizeof port) = &mark;
	}
}

static void parse_differential(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size) {
	(void)type;
	// We just create the trie and store info for future updates. We expect the server will send info about all the differential filters it knows in a short moment.
	const char *name = uplink_parse_string(pool, desc, size);
	sanity(name, "Name of differential filter broken\n");
	dest->diff_addr_store = diff_addr_store_init(pool, name);
}

static void parse_range(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size) {
	// The header is one byte, either 4 or 6 ‒ the address family, then one byte of the netmask. Then there's as many bytes of the address as needed to hold the whole prefix (eg. ceil(netmask/8.0))
	sanity(*size >= 2, "Short data to hold address range header for filter %c, need 2 bytes, have only %zu\n", type->code, *size);
	dest->v6 = (**desc == 6);
	(*desc) ++;
	(*size) --;
	uint8_t netmask = **desc;
	(*desc) ++;
	(*size) --;
	size_t addr_len = dest->v6 ? 16 : 4;
	size_t prefix_len = (netmask + 7) / 8;
	sanity(prefix_len <= addr_len, "Can't have prefix of %hhu biths in an address of length %zu bytes on filter %c\n", netmask, addr_len, type->code);
	sanity(prefix_len <= *size, "Not enough data to hold the address prefix on filter %c (need %zu, have %zu)\n", type->code, prefix_len, *size);
	sanity(netmask, "Empty netmask. I won't pretend being very complex T, I'm %c", type->code);
	uint8_t *mask = mem_pool_alloc(pool, addr_len), *address = mem_pool_alloc(pool, addr_len);
	dest->mask = mask;
	dest->address = address;
	memcpy(address, *desc, prefix_len);
	(*desc) += prefix_len;
	(*size) -= prefix_len;
	memset(address + prefix_len, 0, addr_len - prefix_len);
	memset(mask, 0xFF, prefix_len - 1);
	memset(mask + prefix_len, 0, addr_len - prefix_len);
	uint8_t middle = 0xFF << ((8 - netmask % 8) % 8);
	*(mask + prefix_len - 1) = middle;
	*(address + prefix_len - 1) &= middle;
}

static const struct filter_type types[] = {
	{ // "const true"
		.function = filter_true,
		.code = 'T'
	},
	{ // "const false"
		.function = filter_false,
		.code = 'F'
	},
	{
		.function = filter_not,
		.code = '!',
		.parser = parse_sub
	},
	{
		.function = filter_and,
		.code = '&',
		.parser = parse_many_subs
	},
	{
		.function = filter_or,
		.code = '|',
		.parser = parse_many_subs
	},
	{ // Local IP
		.function = filter_value_match,
		.code = 'i',
		.parser = parse_ip_match
	},
	{ // Remote IP
		.function = filter_value_match,
		.code = 'I',
		.parser = parse_ip_match
	},
	{ // Local port
		.function = filter_value_match,
		.code = 'p',
		.parser = parse_port_match
	},
	{ // Remote port
		.function = filter_value_match,
		.code = 'P',
		.parser = parse_port_match
	},
	{ // A differential IPaddress+port match.
		.function = filter_differential,
		.code = 'd',
		.parser = parse_differential
	},
	{ // The same, but for remote endpoint
		.function = filter_differential,
		.code = 'D',
		.parser = parse_differential
	},
	{ // An address range (for the local address)
		.function = filter_range,
		.code = 'r',
		.parser = parse_range
	},
	{ // An address range on the remote end
		.function = filter_range,
		.code = 'R',
		.parser = parse_range
	}
};

bool filter_apply(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) {
	return filter->function(tmp_pool, filter, packet);
}

static void parse_one(struct mem_pool *pool, struct filter *dest, const uint8_t **desc, size_t *size) {
	if (!*size) {
		ulog(LLOG_ERROR, "Short data reading filter code\n");
		abort();
	}
	uint8_t code = **desc;
	(*desc) ++;
	(*size) --;
	for (size_t i = 0; i < sizeof types / sizeof *types; i ++)
		if (types[i].code == code) {
			memset(dest, 0, sizeof *dest);
			dest->function = types[i].function;
			dest->type = &types[i];
			if (types[i].parser)
				types[i].parser(pool, dest, &types[i], desc, size);
			return;
		}
	sanity(false, "Unknown filter code %c\n", code);
}

struct filter *filter_parse(struct mem_pool *pool, const uint8_t *desc, size_t size) {
	struct filter *result = mem_pool_alloc(pool, sizeof *result);
	if (size) {
		parse_one(pool, result, &desc, &size);
	} else {
		uint8_t data[1];
		*data = 'T';
		const uint8_t *d = data;
		size_t size = 1;
		parse_one(pool, result, &d, &size);
		sanity(size == 0, "Extra data in filter: %zu left\n", size);
	}
	return result;
}

static struct filter *filter_find(const char *name, struct filter *filter) {
	if (filter->diff_addr_store && filter->diff_addr_store->name && strcmp(name, filter->diff_addr_store->name) == 0)
		// Found locally
		return filter;
	for (size_t i = 0; i < filter->sub_count; i ++) {
		struct filter *found = filter_find(name, &filter->subfilters[i]);
		if (found)
			// Found recursively in one of children
			return found;
	}
	// Not found at all
	return NULL;
}

enum diff_store_action filter_action(struct filter *filter, const char *name, uint32_t epoch, uint32_t version, uint32_t *orig_version) {
	struct filter *found = filter_find(name, filter);
	if (!found || !found->diff_addr_store)
		return DIFF_STORE_UNKNOWN;
	return diff_addr_store_action(found->diff_addr_store, epoch, version, orig_version);
}

enum diff_store_action filter_diff_apply(struct mem_pool *tmp_pool, struct filter *filter, const char *name, bool full, uint32_t epoch, uint32_t from, uint32_t to, const uint8_t *diff, size_t diff_size, uint32_t *orig_version) {
	struct filter *found = filter_find(name, filter);
	ulog(LLOG_INFO, "Updating filter %s from version %u to version %u (epoch %u)\n", name, (unsigned)from, (unsigned)to, (unsigned)epoch);
	if (!found || !found->diff_addr_store)
		return DIFF_STORE_UNKNOWN;
	return diff_addr_store_apply(tmp_pool, filter->diff_addr_store, full, epoch, from, to, diff, diff_size, orig_version);
}

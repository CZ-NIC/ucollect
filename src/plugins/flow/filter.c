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

#include "filter.h"

#include "../../core/trie.h"
#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

#define D(MSG, ...) do { ulog(LLOG_ERROR, MSG, __VA_ARGS__); abort(); } while (0)

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
	const struct filter *subfilters;
	struct trie *trie;
	const struct filter_type *type;
	// Info for differential plugins
	const char *name;
	uint32_t epoch, version;
	size_t added, deleted; // Statistics, to know when to re-requested the whole filter config
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
	// Check for IP address match first
	if (trie_lookup(filter->trie, packet->addresses[endpoint], packet->addr_len))
		return true;
	// We now abuse the fact that IP addresses have either 4 or 16 bytes. If it has 6 or 18, it can't be IP only, it must be IP + port
	uint8_t *compound = mem_pool_alloc(tmp_pool, packet->addr_len + sizeof(uint16_t));
	memcpy(compound, packet->addresses[endpoint], packet->addr_len);
	uint16_t port_net = htons(packet->ports[endpoint]);
	memcpy(compound + packet->addr_len, &port_net, sizeof port_net);
	return trie_lookup(filter->trie, compound, packet->addr_len + sizeof port_net);
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
	if (*size < sizeof sub_count)
		D("Short data for number of subfilters for %c\n", type->code);
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
	if (*size < sizeof ip_count)
		D("Short data for number of IP addresses in %c filter, only %zu available\n", type->code, *size);
	memcpy(&ip_count, *desc, sizeof ip_count);
	(*desc) += sizeof ip_count;
	(*size) -= sizeof ip_count;
	ip_count = ntohl(ip_count);
	dest->trie = trie_alloc(pool);
	for (size_t i = 0; i < ip_count; i ++) {
		if (!*size)
			D("Short data for IP address size in %c filter at IP #%zu\n", type->code, i);
		uint8_t ip_size = **desc;
		(*desc) ++;
		(*size) --;
		if (*size < ip_size)
			D("Short data for IP address in %c filter at IP %zu (available %zu, need %hhu)\n", type->code, i, *size, ip_size);
		*trie_index(dest->trie, *desc, ip_size) = &mark;
		(*desc) += ip_size;
		(*size) -= ip_size;
	}
}

static void parse_port_match(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size) {
	uint16_t port_count; // Only 16 bit, there can't be more than that much different ports anyway O:-)
	if (*size < sizeof port_count)
		D("Short data for number of ports in %c filter, only %zu available\n", type->code, *size);
	memcpy(&port_count, *desc, sizeof port_count);
	(*desc) += sizeof port_count;
	(*size) -= sizeof port_count;
	port_count = ntohs(port_count);
	dest->trie = trie_alloc(pool);
	for (size_t i = 0; i < port_count; i ++) {
		uint16_t port;
		if (*size < sizeof port)
			D("Short data for port in %c filter at port #%zu, only %zu available\n", type->code, i, *size);
		memcpy(&port, *desc, sizeof port);
		(*desc) += sizeof port;
		(*size) -= sizeof port;
		*trie_index(dest->trie, (const uint8_t *)&port, sizeof port) = &mark;
	}
}

static void parse_differential(struct mem_pool *pool, struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size) {
	(void)type;
	// We just create the trie and store info for future updates. We expect the server will send info about all the differential filters it knows in a short moment.
	dest->trie = trie_alloc(pool);
	dest->name = uplink_parse_string(pool, desc, size);
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
	D("Unknown filter code %c\n", code);
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
		if (size != 0)
			D("Extra data in filter: %zu left\n", size);
	}
	return result;
}

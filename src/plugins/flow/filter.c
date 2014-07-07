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

#include <assert.h>
#include <string.h>

typedef bool (*filter_fun)(const struct filter *filter, const struct packet_info *packet);

struct filter {
	filter_fun function;
	struct trie *trie;
	struct filter *subfilters;
};

struct filter_type;

typedef void (*filter_parser)(struct mem_pool *pool, const struct filter *dest, const struct filter_type *type, const uint8_t **desc, size_t *size);

struct filter_type {
	filter_fun function;
	filter_parser parser;
	uint8_t code;
};

static bool filter_true(const struct filter *filter, const struct packet_info *packet) {
	(void) filter;
	(void) packet;
	return true;
}

static const struct filter_type types[] = {
	{ // "const true"
		.function = filter_true,
		.code = 'T'
	}
};

bool filter_apply(const struct filter *filter, const struct packet_info *packet) {
	return filter->function(filter, packet);
}

void parse_one(struct mem_pool *pool, struct filter *dest, const uint8_t **desc, size_t *size) {
	if (!*size)
		die("Short data reading filter code\n");
	uint8_t code = **desc;
	(*desc) ++;
	(*size) --;
	for (size_t i = 0; i < sizeof types / sizeof *types; i ++)
		if (types[i].code == code) {
			memset(dest, 0, sizeof *dest);
			dest->function = types[i].function;
			if (types[i].parser)
				types[i].parser(pool, dest, &types[i], desc, size);
			return;
		}
	die("Unknown filter code %c\n", code);
}

struct filter *filter_parse(struct mem_pool *pool, const uint8_t *desc, size_t size) {
	struct filter *result = mem_pool_alloc(pool, sizeof *result);
	if (size) {
		parse_one(pool, result, &desc, &size);
	} else {
		*result = (struct filter) { .function = filter_true };
	}
	return NULL;
}

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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef UCOLLECT_FLOW_DIFF_STORE_H
#define UCOLLECT_FLOW_DIFF_STORE_H

enum diff_store_action {
	DIFF_STORE_INCREMENTAL, // Ask for a differential update,
	DIFF_STORE_FULL,
	DIFF_STORE_CONFIG_RELOAD,
	DIFF_STORE_NO_ACTION,
	DIFF_STORE_UNKNOWN
};

struct diff_addr_store {
	const char *name;
	struct trie *trie;
	struct mem_pool *pool;
	uint32_t epoch, version;
	size_t added, deleted; // Statistics, to know when to re-requested the whole filter config
};

struct diff_addr_store *diff_addr_store_init(struct mem_pool *pool, const char *name);
enum diff_store_action diff_addr_store_action(struct diff_addr_store *store, uint32_t epoch, uint32_t version, uint32_t *orig_version);
enum diff_store_action diff_addr_store_apply(struct mem_pool *tmp_pool, struct diff_addr_store *store, bool full, uint32_t epoch, uint32_t from, uint32_t to, const uint8_t *diff, size_t diff_size, uint32_t *orig_version);

#endif

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

#ifndef UCOLLECT_DIFF_STORE_H
#define UCOLLECT_DIFF_STORE_H

#include <stdlib.h>
#include <stdint.h>

struct trie;
struct mem_pool;

enum diff_store_action {
	DIFF_STORE_INCREMENTAL, // Ask for a differential update,
	DIFF_STORE_FULL,
	DIFF_STORE_CONFIG_RELOAD,
	DIFF_STORE_NO_ACTION,
	DIFF_STORE_UNKNOWN
};

struct diff_addr_store;

typedef void (*addr_hook_t)(struct diff_addr_store *store, const uint8_t *addr, size_t addr_len, void *userdata);
typedef void (*addr_clear_hook_t)(struct diff_addr_store *store, void *userdata);

struct diff_addr_store {
	const char *name;
	struct trie *trie;
	struct mem_pool *pool;
	uint32_t epoch, version;
	size_t added, deleted; // Statistics, to know when to re-requested the whole filter config
	/* The following 4 members - 3 hooks and userdata - may be filled directly by the user.
	 * The hooks would be called at appropriate moments. All of them happen before the update
	 * in the data structures. It is legal not to fill the hooks in (or set them as NULL),
	 * they are called only if set. */
	addr_hook_t add_hook;
	addr_hook_t remove_hook;
	addr_clear_hook_t clear_hook;
	void *userdata;
};

#endif

#include "../../core/pluglib_macros.h"

// memory pool to allocate from, name. The name is not copied, it is expected to exist for the whole lifetime of the structure.
PLUGLIB_FUNC(diff_addr_store_init, struct diff_addr_store *, struct mem_pool *, const char *)
// Copy (target, source, tmp_pool). The name, and mempool are not copied, only the active addresses.
PLUGLIB_FUNC(diff_addr_store_cp, void, struct diff_addr_store *, const struct diff_addr_store *, struct mem_pool *)
PLUGLIB_FUNC(diff_addr_store_action, enum diff_store_action, struct diff_addr_store *, uint32_t, uint32_t, uint32_t *)
PLUGLIB_FUNC(diff_addr_store_apply, enum diff_store_action, struct mem_pool *, struct diff_addr_store *, bool, uint32_t, uint32_t, uint32_t, const uint8_t *, size_t, uint32_t *)


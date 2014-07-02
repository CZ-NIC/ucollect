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

#ifndef UCOLLECT_CORE_TRIE_H
#define UCOLLECT_CORE_TRIE_H

/*
 * This module holds a compressed trie (radix tree) with binary keys of arbitrary length.
 *
 * The trie can be used to access values indexed by the keys fast and new keys can
 * be added at any time. However, it doesn't support deletions and it can be only
 * destroyed as a whole.
 */

#include <stdint.h>
#include <stdlib.h>

// User data to store in the trie. Each module/plugin can have different implementation.
struct trie_data;
// Opaque handle to the trie internal structures.
struct trie;

struct mem_pool;

/*
 * Allocate new empty trie which will use the given memory pool to construct the structures.
 *
 * There's no deallocation routine for trie. You have to reset the memory pool.
 */
struct trie *trie_alloc(struct mem_pool *pool) __attribute__((nonnull));
/*
 * Access a position in the trie. It is allowed (and expected) for the caller to change the data pointer.
 *
 * The pointer becomes invalid after any other trie operation. It is OK to set the pointer to data, but then
 * it needs to be forgotten. If the key was accessed before and the value set, the same value (the internal
 * pointer) is returned. Otherwise, a new NULL pointer is allocated from the memory pool and it can
 * be changed.
 */
struct trie_data **trie_index(struct trie *trie, const uint8_t *key, size_t key_size) __attribute__((nonnull(1)));
// Return count of different positions accessed by trie_index
size_t trie_size(struct trie *trie) __attribute__((nonnull));
// Walk the whole trie and call the callback for each key previously accessed by trie_index. The value in key pointer will change (it is not valid after end of the callback).
typedef void (*trie_walk_callback)(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata);
void trie_walk(struct trie *trie, trie_walk_callback callback, void *userdata, struct mem_pool *temp_pool) __attribute__((nonnull(1,2,4)));

#endif

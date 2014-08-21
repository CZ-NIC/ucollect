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

#include "trie.h"
#include "mem_pool.h"
#include "util.h"

#include <stdbool.h>
#include <string.h>
#include <assert.h>

struct trie_node {
	struct trie_data *data;
	const uint8_t *key;
	size_t key_size;
	struct trie_node *head, *tail, *next, *prev;
	bool active;
};

#define LIST_NODE struct trie_node
#define LIST_BASE struct trie_node
#define LIST_PREV prev
#define LIST_NAME(X) trie_##X
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_REMOVE
#include "link_list.h"

struct trie {
	struct trie_node root;
	size_t active_count;
	size_t max_key_len;
	struct mem_pool *pool;
};

struct trie *trie_alloc(struct mem_pool *pool) {
	ulog(LLOG_DEBUG, "Allocating new trie\n");
	struct trie *result = mem_pool_alloc(pool, sizeof *result);
	*result = (struct trie) {
		.pool = pool
	};
	return result;
}

size_t trie_size(struct trie *trie) {
	return trie->active_count;
}

static void walk_node(struct trie_node *node, trie_walk_callback callback, void *userdata, uint8_t *keybuf, size_t keypos) {
	ulog(LLOG_DEBUG_VERBOSE, "Walk: %zu + %zu\n", keypos, node->key_size);
	memcpy(keybuf + keypos, node->key, node->key_size);
	keypos += node->key_size;
	if (node->active) {
		keybuf[keypos] = '\0';
		callback(keybuf, keypos, node->data, userdata);
	}
	LFOR(trie, child, node)
		walk_node(child, callback, userdata, keybuf, keypos);
}

void trie_walk(struct trie *trie, trie_walk_callback callback, void *userdata, struct mem_pool *temp_pool) {
	ulog(LLOG_DEBUG, "Walking trie with %zu active nodes\n", trie->active_count);
	uint8_t *keybuf = mem_pool_alloc(temp_pool, trie->max_key_len + 1);
	walk_node(&trie->root, callback, userdata, keybuf, 0);
}

// Longest common prefix
static size_t lcp(const uint8_t *_1, size_t s1, const uint8_t *_2, size_t s2) {
	for (size_t i = 0; i < s1 && i < s2; i ++)
		if (_1[i] != _2[i])
			return i;
	return s1 < s2 ? s1 : s2;
}

static struct trie_data **trie_new_node(struct trie *trie, struct trie_node *parent, const uint8_t *key, size_t key_size, bool insert_new) {
	if (!insert_new)
		return NULL;
	ulog(LLOG_DEBUG_VERBOSE, "Creating new node with %zu bytes of key\n", key_size);
	struct trie_node *new = trie_append_pool(parent, trie->pool);
	new->active = true;
	trie->active_count ++;
	new->head = new->tail = NULL; // No children yet
	new->data = NULL;
	uint8_t *new_key = mem_pool_alloc(trie->pool, key_size);
	new->key = new_key;
	memcpy(new_key, key, key_size);
	new->key_size = key_size;
	return &new->data;
}

static struct trie_data **trie_index_internal(struct trie *trie, struct trie_node *node, const uint8_t *key, size_t key_size, bool insert_new) {
	size_t prefix = lcp(key, key_size, node->key, node->key_size);
	if (prefix == node->key_size) { // We went the whole length of the node's path
		// Eath the part of key we already used
		ulog(LLOG_DEBUG_VERBOSE, "Eaten %zu bytes of key\n", prefix);
		key += prefix;
		key_size -= prefix;
		if (key_size == 0) {
			// We found the position
			ulog(LLOG_DEBUG_VERBOSE, "Trie exact hit\n");
			if (!node->active && insert_new) {
				ulog(LLOG_DEBUG_VERBOSE, "Making node active\n");
				node->active = true;
				trie->active_count ++;
			}
			return &node->data; // Will be NULL for sure if not active
		} else {
			// We have more of key to process
			LFOR(trie, child, node) {
				assert(child->key_size);
				if (*child->key == *key) {
					ulog(LLOG_DEBUG_VERBOSE, "Descending into a child %hhu/'%c'\n", *key, *key);
					// Move the child to the front. In practice, most of the traffic happens with similar packets (same addresses, etc), so have them to the front most of the time
					trie_remove(node, child);
					trie_insert_after(node, child, NULL);
					return trie_index_internal(trie, child, key, key_size, insert_new);
				}
			}
			// Not found any matching child, create a new one
			return trie_new_node(trie, node, key, key_size, insert_new);
		}
	} else if (insert_new) {
		ulog(LLOG_DEBUG_VERBOSE, "Splitting node with key of %zu bytes after %zu bytes\n", node->key_size, prefix);
		/*
		 * We traversed only part of the path. We need to split it in half, and create a new node for the
		 * rest of the path, and another new node for the one we want to index.
		 */
		struct trie_node *new = mem_pool_alloc(trie->pool, sizeof *new);
		// Move the content to the new node
		*new = *node;
		// Rip out the new node from the list
		new->next = new->prev = NULL;
		// Move the new key after the prefix
		new->key += prefix;
		new->key_size -= prefix;
		// Reset data in the old node
		node->active = false;
		node->data = NULL;
		node->head = NULL;
		node->tail = NULL;
		node->key_size = prefix;
		// Add the new node as child
		trie_insert_after(node, new, NULL);
		// And now add the rest of the index at the split node
		return trie_new_node(trie, node, key + prefix, key_size - prefix, insert_new);
	} else
		return NULL; // Not inserting a new one
}

struct trie_data **trie_index(struct trie *trie, const uint8_t *key, size_t key_size) {
	ulog(LLOG_DEBUG_VERBOSE, "Indexing trie by %zu bytes of key\n", key_size);
	if (key_size > trie->max_key_len)
		trie->max_key_len = key_size;
	return trie_index_internal(trie, &trie->root, key, key_size, true);
}

struct trie_data *trie_lookup(struct trie *trie, const uint8_t *key, size_t key_size) {
	ulog(LLOG_DEBUG_VERBOSE, "Looking up in trie with %zu bytes of key\n", key_size);
	struct trie_data **data = trie_index_internal(trie, &trie->root, key, key_size, false);
	if (data)
		return *data;
	else
		return NULL;
}

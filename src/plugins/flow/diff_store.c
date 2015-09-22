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

#include "diff_store.h"

#include "../../core/trie.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"

#include <assert.h>

struct trie_data {
	int dummy; // Just to prevent warning about empty struct
};

static struct trie_data mark; // To have a valid pointer to something, not used by itself

struct diff_addr_store *diff_addr_store_init(struct mem_pool *pool, const char *name) {
	assert(name);
	struct diff_addr_store *result = mem_pool_alloc(pool, sizeof *result);
	*result = (struct diff_addr_store) {
		.trie = trie_alloc(pool),
		.name = name,
		.pool = pool
	};
	return result;
}

enum diff_store_action diff_addr_store_action(struct diff_addr_store *store, uint32_t epoch, uint32_t version, uint32_t *orig_version) {
	assert(store);
	if (epoch == store->epoch && version == store->version)
		return DIFF_STORE_NO_ACTION; // Nothing changed. Ignore the update.
	size_t active = store->added - store->deleted;
	ulog(LLOG_DEBUG, "%zu active, %zu deleted\n", active, store->deleted);
	if (active * 10 < store->deleted && store->deleted > 100)
		return DIFF_STORE_CONFIG_RELOAD; // There's too much cruft around. Reload the whole config and force freeing memory by that.
	if (epoch != store->epoch)
		return DIFF_STORE_FULL;
	*orig_version = store->version;
	return DIFF_STORE_INCREMENTAL;
}

/*
 * We don't use the last bit, there's no address with odd length. We use that bit for something else.
 *
 * Actually, we expect these values:
 * • 4: IPv4 address
 * • 6: IPv4 + port
 * • 16: IPv6 address
 * • 18: IPv6 + port
 */
const uint8_t size_mask = 16 + 8 + 4 + 2;
const uint8_t add_mask = 1;

#ifdef DEBUG
static void debug_dump(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	struct mem_pool *pool = userdata;
	const char *active = data ? "Active" : "Inactive";
	char *hex = mem_pool_hex(pool, key, key_size);
	ulog(LLOG_DEBUG_VERBOSE, "Key: %s: %s\n", hex, active);
}
#endif

enum diff_store_action diff_addr_store_apply(struct mem_pool *tmp_pool, struct diff_addr_store *store, bool full, uint32_t epoch, uint32_t from, uint32_t to, const uint8_t *diff, size_t diff_size, uint32_t *orig_version) {
	assert(tmp_pool);
	assert(store);
	if (epoch != store->epoch && !full)
		// This is for different epoch than we have. Resynchronize!
		return DIFF_STORE_FULL;
	if (from != store->version && !full) {
		*orig_version = store->version;
		return DIFF_STORE_INCREMENTAL;
	}
	if (full && store->added != store->deleted) {
		// We're doing a full update and there's something in the trie. Reset it.
		store->deleted = store->added;
		store->trie = trie_alloc(store->pool);
	}
	size_t addr_no = 0;
	while (diff_size --) {
		uint8_t flags = *(diff ++);
		ulog(LLOG_DEBUG_VERBOSE, "Address flags: %hhu\n", flags);
		uint8_t addr_len = flags & size_mask;
		if (addr_len > diff_size) {
			ulog(LLOG_ERROR, "Filter diff for %s corrupted, need %hhu bytes, have only %zu\n", store->name, addr_len, diff_size);
			abort();
		}
		struct trie_data **data = trie_index(store->trie, diff, addr_len);
		bool add = flags & add_mask;
		if (add) {
			if (*data) {
				ulog(LLOG_WARN, "Asked to add an address %s (#%zu) of size %hhu to filter %s, but that already exists\n", mem_pool_hex(tmp_pool, diff, addr_len), addr_no, addr_len, store->name);
			} else {
				*data = &mark;
				store->added ++;
			}
		} else {
			if (*data) {
				*data = NULL;
				store->deleted ++;
			} else {
				ulog(LLOG_WARN, "Asked to delete an address %s (#%zu) of size %hhu from filter %s, but that is not there\n", mem_pool_hex(tmp_pool, diff, addr_len), addr_no, addr_len, store->name);
			}
		}
		diff += addr_len;
		diff_size -= addr_len;
		addr_no ++;
	}
	store->epoch = epoch;
	store->version = to;
	ulog(LLOG_DEBUG, "Filter %s updated:\n", store->name);
#ifdef DEBUG
	trie_walk(store->trie, debug_dump, tmp_pool, tmp_pool);
#endif
	return DIFF_STORE_NO_ACTION;
}

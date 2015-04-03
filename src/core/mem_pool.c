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

#include "mem_pool.h"
#include "util.h"
#include "tunable.h"

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void store(struct mem_pool *pool);
static void drop(struct mem_pool *pool);

#ifdef MEM_POOL_DEBUG

#define POOL_CANARY_BEGIN 0x783A7BF4
#define POOL_CANARY_END   0x0F3B239A

struct pool_chunk {
	struct pool_chunk *next;
	size_t length;
	uint32_t canary;
	uint8_t data[];
};

struct mem_pool {
	struct pool_chunk *head, *tail;
	size_t pool_index;
	size_t used, allocated, requests;
	char name[];
};

#define LIST_NODE struct pool_chunk
#define LIST_BASE struct mem_pool
#define LIST_NAME(X) pool_##X
#define LIST_WANT_INSERT_AFTER
#include "link_list.h"

struct mem_pool *mem_pool_create(const char *name) {
	struct mem_pool *pool = malloc(sizeof *pool + strlen(name) + 1);
	*pool = (struct mem_pool) {
		.head = NULL
	};
	store(pool);
	strcpy(pool->name, name);
	ulog(LLOG_DEBUG, "Created pool %s\n", name);
	return pool;
}

void *mem_pool_alloc(struct mem_pool *pool, size_t size) {
	struct pool_chunk *chunk = malloc(sizeof *chunk + size + sizeof(uint32_t));
	chunk->canary = POOL_CANARY_BEGIN;
	*(uint32_t *) (chunk->data + size) = POOL_CANARY_END;
	chunk->length = size;
	pool_insert_after(pool, chunk, NULL);
	ulog(LLOG_DEBUG_VERBOSE, "Allocated %zu bytes from %s at address %p\n", size, pool->name, (void *) chunk);
	pool->used += size;
	pool->allocated += sizeof *chunk + size + sizeof(uint32_t);
	pool->requests ++;
	return chunk->data;
}

void mem_pool_reset(struct mem_pool *pool) {
	while (pool->head) {
		struct pool_chunk *current = pool->head;
		pool->head = current->next;
		assert(current->canary == POOL_CANARY_BEGIN);
		assert(*(uint32_t *) (current->data + current->length) == POOL_CANARY_END);
		ulog(LLOG_DEBUG_VERBOSE, "Freeing %p of size %zu from %s\n", (void *) current, current->length, pool->name);
		free(current);
	}
	pool->tail = NULL;
	pool->allocated = 0;
	pool->used = 0;
	pool->requests = 0;
}

void mem_pool_destroy(struct mem_pool *pool) {
	mem_pool_reset(pool);
	ulog(LLOG_DEBUG, "Destroyed pool %s\n", pool->name);
	drop(pool);
	free(pool);
}

#else

struct pool_page {
	// Next page in linked list (for freeing them on reset or destroy).
	struct pool_page *next;
	// How many bytes the page has (total, with the header).
	size_t size;
	// This should be well aligned, because the previous is size_t.
	unsigned char data[];
};

/*
 * Cache few pages (of the unit size, not the bigger ones) so we don't keep allocating
 * and returning them too often.
 */
static struct pool_page *page_cache[PAGE_CACHE_SIZE];
static size_t page_cache_size;

struct mem_pool {
	// First page.
	struct pool_page *first;
	// Where do we allocate next?
	unsigned char *pos;
	// How many bytes there are for allocations.
	size_t available;
	size_t pool_index;
	size_t used, allocated, requests;
	// The name of this memory pool (for debug and errors).
	char name[];
};

// Get a page of given total size. Data size will be smaller.
static struct pool_page *page_get(size_t size, const char *name) {
	struct pool_page *result;
	const char *cached = "";
	if (size == PAGE_SIZE && page_cache_size) {
		// If it is a single, take it from the cache
		result = page_cache[-- page_cache_size];
		cached = " (cached)";
#ifdef DEBUG
		memset(result, '%', size);
#endif
		result->size = size;
	} else {
		result = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (result == MAP_FAILED)
			die("Couldn't get page of %zu bytes for pool '%s' (%s)\n", size, name, strerror(errno));
#ifdef DEBUG
		memset(result, '#', size);
#endif
		result->size = size;
	}
	result->next = NULL;
	ulog(LLOG_DEBUG, "Got page %zu large for pool '%s' (%p) %s\n", size, name, (void *) result, cached);
	return result;
}

// Release a given page (previously allocated by page_get).
static void page_return(struct pool_page *page, const char *name) {
	ulog(LLOG_DEBUG, "Releasing page %zu large from pool '%s' (%p) %s\n", page->size, name, (void *) page, (page->size == PAGE_SIZE && page_cache_size < PAGE_CACHE_SIZE) ? " (cached)" : "");
	if (page->size == PAGE_SIZE && page_cache_size < PAGE_CACHE_SIZE)
		// A single page can be put into the cache, if it is not already full
		page_cache[page_cache_size ++] = page;
	else if (munmap(page, page->size) != 0)
		die("Couldn't return page %p of %zu bytes from pool '%s' (%s)\n", (void *) page, page->size, name, strerror(errno));
}

static const size_t align_for = sizeof(unsigned char *);

/*
 * Allocate some memory from the given position of given size. Updates pos and available.
 * Returns the pointer or NULL if there is not enough memory.
 */
static void *page_alloc(unsigned char **pos, size_t *available, size_t size) {
	if (*available < size)
		return NULL;

	// Check the *pos is aligned. Check after the size check, as the last allocation that fits may not align.
	assert((*pos - (unsigned char *) NULL) % align_for == 0);

	void *result = *pos;

	size = (size + align_for - 1) / align_for * align_for;
	if (size > *available)
		size = *available;
	*pos += size;
	*available -= size;

	return result;
}

static void page_walk_and_delete(struct pool_page *page, const char *name) {
	// As the name is in the first page, do it from the end, using recursion.
	if (page) {
		page_walk_and_delete(page->next, name);
		page_return(page, name);
	}
}

struct mem_pool *mem_pool_create(const char *name) {
	ulog(LLOG_DEBUG, "Creating memory pool '%s'\n", name);
	size_t name_len = 1 + strlen(name);
	// Get the first page for the pool
	assert(PAGE_SIZE > sizeof(struct pool_page) + sizeof(struct mem_pool) + name_len);
	struct pool_page *page = page_get(PAGE_SIZE, name);

	// Allocate the pool control structure from the page
	unsigned char *pos = page->data;
	size_t available = page->size - sizeof *page;
	struct mem_pool *pool = page_alloc(&pos, &available, sizeof(struct mem_pool) + name_len);

	// Initialize the values.
	assert(pool); // Should not fail here, the page should be large enough and empty.
	*pool = (struct mem_pool) {
		.first = page,
		.pos = pos,
		.available = available,
		.allocated = PAGE_SIZE
	};
	store(pool);
	strcpy(pool->name, name); // OK to use strcpy, we allocated enough extra space.

	return pool;
}

void mem_pool_destroy(struct mem_pool *pool) {
	ulog(LLOG_DEBUG, "Destroying memory pool '%s'\n", pool->name);
	drop(pool);
	/*
	 * Walk the pages and release each of them. The pool itself is in one of them,
	 * so there's no need to explicitly delete it.
	 *
	 * Start from the first one, to delete all.
	 */
	page_walk_and_delete(pool->first, pool->name);
}

void *mem_pool_alloc(struct mem_pool *pool, size_t size) {
	void *result = page_alloc(&pool->pos, &pool->available, size);
	if (!result) { // There's not enough space in this page, get another one.
		/*
		 * Round the size to the nearest bigger full page. This is here because
		 * the request can be larger than a single page.
		 */
		size_t page_size = (size + sizeof(struct pool_page) + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
		/*
		 * Get the page and put it into the pool. Keep the first page first,
		 * it is special as it contains the pool itself, so we want to have
		 * it at hand. Otherwise, the order does not matter, it is only
		 * for clean up.
		 */
		struct pool_page *page = page_get(page_size, pool->name);
		page->next = pool->first->next;
		pool->first->next = page;
		// Allocate.
		size_t available = page->size - sizeof *page;
		unsigned char *pos = page->data;
		result = page_alloc(&pos, &available, size);
		assert(result); // We asked for page large enough, must not fail.
		/*
		 * Update the internal data in the pool. It may have happened this
		 * was a large allocation close to page size and the rest of the
		 * previous page is bigger. So we check.
		 */
		if (available > pool->available) {
			pool->available = available;
			pool->pos = pos;
		}
		pool->allocated += page_size;
	}
	pool->used += size;
	pool->requests ++;
	return result;
}

void mem_pool_reset(struct mem_pool *pool) {
	// Release all the pages except the first one (may be NULL).
	page_walk_and_delete(pool->first->next, pool->name);
	// Reset the pool position
	pool->pos = pool->first->data;
	pool->available = pool->first->size - sizeof *pool->first;
	pool->first->next = NULL;
	pool->allocated = PAGE_SIZE;
	pool->used = 0;
	pool->requests = 0;
	// Allocate the pool (again) from the page. It is already there.
	struct mem_pool *the_pool = page_alloc(&pool->pos, &pool->available, sizeof *pool + 1 + strlen(pool->name));
	assert(pool == the_pool); // It should be the same pool.
}

#endif

static struct mem_pool **pools;
size_t pool_count;

static void store(struct mem_pool *pool) {
	pools = realloc(pools, (++ pool_count) * sizeof *pools);
	pools[pool_count - 1] = pool;
	pool->pool_index = pool_count - 1;
}

static void drop(struct mem_pool *pool) {
	assert(pool_count > pool->pool_index);
	assert(pool == pools[pool->pool_index]);
	pools[pool->pool_index] = pools[pool_count - 1];
	pools[pool->pool_index]->pool_index = pool->pool_index;
	pools = realloc(pools, (-- pool_count) * sizeof *pools);
}

char *mem_pool_strdup(struct mem_pool *pool, const char *string) {
	size_t length = strlen(string);
	char *result = mem_pool_alloc(pool, length + 1);
	strcpy(result, string);
	return result;
}

char *mem_pool_printf(struct mem_pool *pool, const char *format, ...) {
	va_list args, args_copy;
	va_start(args, format);
	va_copy(args_copy, args);
	// First find out how many bytes are needed
	size_t needed = vsnprintf(NULL, 0, format, args) + 1;
	// Allocate and render the result
	char *result = mem_pool_alloc(pool, needed);
	size_t written = vsnprintf(result, needed, format, args_copy);
	va_end(args);
	va_end(args_copy);
	// Make sure the amount written is the same as promised.
	assert(written == needed - 1);
	return result;
}

char *mem_pool_hex(struct mem_pool *pool, const uint8_t *data, size_t size) {
	char *result = mem_pool_alloc(pool, 3*size);
	for (size_t i = 0; i < size; i ++)
		sprintf(result + 3*i, "%.2hhX%c", data[i], (i+1) % 4 ? ':' : ' ');
	result[size ? 3*size-1 : 0] = '\0';
	return result;
}

char *mem_pool_stats(struct mem_pool *tmp_pool) {
	char **parts = mem_pool_alloc(tmp_pool, pool_count * sizeof *parts);
	size_t len = 1;
	for (size_t i = 0; i < pool_count; i ++) {
		struct mem_pool *p = pools[i];
		parts[i] = mem_pool_printf(tmp_pool, "%s: %zu/%zu (%zu)", p->name, p->used, p->allocated, p->requests);
		len += 2 + strlen(parts[i]);
	}
	char *result = mem_pool_alloc(tmp_pool, len);
	size_t pos = 0;
	for (size_t i = 0; i < pool_count; i ++) {
		if (pos) {
			memcpy(result + pos, ", ", 2);
			pos += 2;
		}
		size_t l = strlen(parts[i]);
		memcpy(result + pos, parts[i], l);
		pos += l;
	}
	result[pos] = '\0';
	return result;
}

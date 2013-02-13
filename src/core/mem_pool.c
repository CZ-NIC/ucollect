#include "mem_pool.h"
#include "util.h"

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

struct pool_page {
	// Next page in linked list (for freeing them on reset or destroy).
	struct pool_page *next;
	// How many bytes the page has (total, with the header).
	size_t size;
	// This should be well aligned, because the previous is size_t.
	unsigned char data[];
};

struct mem_pool {
	// First page.
	struct pool_page *first;
	// Where do we allocate next?
	unsigned char *pos;
	// How many bytes there are for allocations.
	size_t available;
	// The name of this memory pool (for debug and errors).
	char name[];
};

// Get a page of given total size. Data size will be smaller.
static struct pool_page *page_get(size_t size, const char *name) {
	ulog(LOG_DEBUG, "Getting page %zu large for pool '%s'\n", size, name);
	// TODO: Some page caching
	struct pool_page *result = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED)
		die("Couldn't get page of %zu bytes for pool '%s' (%s)\n", size, name, strerror(errno));
	result->next = NULL;
	result->size = size;
	return result;
}

// Release a given page (previously allocated by page_get).
static void page_return(struct pool_page *page, const char *name) {
	ulog(LOG_DEBUG, "Releasing page %zu large from pool '%s'\n", page->size, name);
	// TODO: Cache the page?
	if (munmap(page, page->size) != 0)
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
	ulog(LOG_DEBUG, "Creating memory pool '%s'\n", name);
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
		.available = available
	};
	strcpy(pool->name, name); // OK to use strcpy, we allocated enough extra space.

	return pool;
}

void mem_pool_destroy(struct mem_pool *pool) {
	ulog(LOG_DEBUG, "Destroying memory pool '%s'\n", pool->name);
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
	}
	return result;
}

void mem_pool_reset(struct mem_pool *pool) {
	// Release all the pages except the first one (may be NULL).
	page_walk_and_delete(pool->first->next, pool->name);
	// Reset the pool position
	pool->pos = pool->first->data;
	pool->available = pool->first->size - sizeof *pool->first;
	// Allocate the pool (again) from the page.
	struct mem_pool *the_pool = page_alloc(&pool->pos, &pool->available, sizeof *pool + 1 + strlen(pool->name));
	assert(pool == the_pool); // It should be the same pool.
}

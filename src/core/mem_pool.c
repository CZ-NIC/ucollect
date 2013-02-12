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
};

// Get a page of given total size.
static struct pool_page *page_get(size_t size) {
	// TODO: Some page caching
	struct pool_page *result = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED)
		die("Couldn't get page of %zu bytes (%s)", size, strerror(errno));
	result->next = NULL;
	result->size = size - sizeof(struct pool_page);
	return result;
}

// Release a given page (previously allocated by page_get).
static void page_return(struct pool_page *page) {
	// TODO: Cache the page?
	if (munmap(page, page->size) != 0)
		die("Couldn't return page %p of %zu bytes (%s)", (void *) page, page->size, strerror(errno));
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

static void page_walk_and_delete(struct pool_page *page) {
	while (page) {
		struct pool_page *next_page = page->next;
		page_return(page);
		page = next_page;
	}
}

struct mem_pool *mem_pool_create() {
	// Get the first page for the pool
	assert(PAGE_SIZE > sizeof(struct pool_page) + sizeof(struct mem_pool));
	struct pool_page *page = page_get(PAGE_SIZE);

	// Allocate the pool control structure from the page
	unsigned char *pos = page->data;
	size_t available = page->size;
	struct mem_pool *pool = page_alloc(&pos, &available, sizeof(struct mem_pool));

	// Initialize the values.
	assert(pool); // Should not fail here, the page should be large enough and empty.
	*pool = (struct mem_pool) {
		.first = page,
		.pos = pos,
		.available = available
	};

	return pool;
}

void mem_pool_destroy(struct mem_pool *pool) {
	/*
	 * Walk the pages and release each of them. The pool itself is in one of them,
	 * so there's no need to explicitly delete it.
	 *
	 * Start from the first one, to delete all.
	 */
	page_walk_and_delete(pool->first);
}

void *mem_pool_alloc(struct mem_pool *pool, size_t size) {
	void *result = page_alloc(&pool->pos, &pool->available, size);
	if (!result) {
		// There's not enough space in this page, get another one.
		assert(0); // TODO: Not implemented yet
	}
	return result;
}

void mem_pool_reset(struct mem_pool *pool) {
	// TODO: Not implemented
}

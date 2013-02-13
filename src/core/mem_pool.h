#ifndef UCOLLECT_MEM_POOL_H
#define UCOLLECT_MEM_POOL_H

#include <stddef.h>

// Opaque handle to a memory pool.
struct mem_pool;

// Create a memory pool. The name is debug and error message aid.
struct mem_pool *mem_pool_create(const char *name) __attribute__((malloc));
// Destroy a memory pool, freeing all its memory as well.
void mem_pool_destroy(struct mem_pool *pool) __attribute__((nonnull));

// Allocate bit of memory from given memory pool. Never returns NULL (crashes if it can't allocate)
void *mem_pool_alloc(struct mem_pool *pool, size_t size) __attribute__((malloc)) __attribute__((nonnull));
// Free all memory allocated from this memory pool. The pool can be used to get more allocations.
void mem_pool_reset(struct mem_pool *pool) __attribute__((nonnull));

// Some convenience functions
char *mem_pool_strdup(struct mem_pool *pool, const char *string) __attribute__((malloc)) __attribute__((nonnull));

#endif

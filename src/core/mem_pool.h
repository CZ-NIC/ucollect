#ifndef UCOLLECT_MEM_POOL_H
#define UCOLLECT_MEM_POOL_H

#include <stddef.h>

struct mem_pool;

struct mem_pool *mem_pool_create() __attribute__((malloc));
void mem_pool_destroy(struct mem_pool *pool) __attribute__((nonnull));

void *mem_pool_alloc(struct mem_pool *pool, size_t size) __attribute__((malloc)) __attribute__((nonnull));
void mem_pool_reset(struct mem_pool *pool) __attribute__((nonnull));

#endif

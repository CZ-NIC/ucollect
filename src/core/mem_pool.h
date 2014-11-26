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

#ifndef UCOLLECT_MEM_POOL_H
#define UCOLLECT_MEM_POOL_H

#include <stddef.h>
#include <stdint.h>

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

// Copy a string to memory from the pool
char *mem_pool_strdup(struct mem_pool *pool, const char *string) __attribute__((malloc)) __attribute__((nonnull));
// Format a string by printf formatting to memory from the pool and return
char *mem_pool_printf(struct mem_pool *pool, const char *format, ...) __attribute__((malloc)) __attribute__((nonnull(1, 2))) __attribute__((format(printf, 2, 3)));
// Format binary data to hex
char *mem_pool_hex(struct mem_pool *pool, const uint8_t *data, size_t size) __attribute__((malloc)) __attribute__((nonnull));

// Provide a string with statistics about all the memory pools. The result is allocated from tmp_pool
char *mem_pool_stats(struct mem_pool *tmp_pool) __attribute__((malloc)) __attribute__((nonnull));

#endif

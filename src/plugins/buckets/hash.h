#ifndef UCOLLECT_BUCKET_HASH_H
#define UCOLLECT_BUCKET_HASH_H

#include <stdint.h>
#include <stddef.h>

struct mem_pool;

// Gen enough random data for these hash functions
const uint32_t *gen_hash_data(uint64_t seed_base, size_t hash_count, size_t hash_line_size, struct mem_pool *pool);

// Compute hash of given key. Provide random data for the computation.
uint32_t hash(const uint8_t *key, size_t key_size, const uint32_t *hash_data);

#endif

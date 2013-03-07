#include "hash.h"
#include "rng.h"

#include "../../core/mem_pool.h"

const uint32_t *gen_hash_data(uint64_t seed_base, size_t hash_count, size_t hash_line_size, struct mem_pool *pool) {
	struct rng_seed seed = rng_seed_init(seed_base);
	// 256 possible values of byte, a block of bytes for each position in eatch hash
	size_t size = hash_line_size * hash_count;
	uint32_t *result = mem_pool_alloc(pool, size * sizeof *result);
	for (size_t i = 0; i < size; i ++)
		// Use our random generator. We need the random numbers to be the same every time/everywhere.
		result[i] = rng_get(&seed);
	return result;
}

/*
 * This random function should be uniformly distributed and with different hash_data, the
 * hash functions should be independent. The only disadvantage is we need quite some random
 * data.
 *
 * The only thing to worry about is how random the random data is.
 */
uint32_t hash(const uint8_t *key, size_t key_size, const uint8_t *hash_data) {
	uint32_t result = 0;
	for (size_t i = 0; i < key_size; i ++) {
		// Pick a random number based on the next byte of input
		result ^= hash_data[key[i]];
		// Move to the next block for the next key
		hash_data += 256;
	}
	return result;
}

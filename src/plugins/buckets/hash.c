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
uint32_t hash(const uint8_t *key, size_t key_size, const uint32_t *hash_data) {
	uint32_t result = 0;
	for (size_t i = 0; i < key_size; i ++) {
		// Pick a random number based on the next byte of input
		result ^= hash_data[key[i]];
		// Move to the next block for the next key
		hash_data += 256;
	}
	return result;
}

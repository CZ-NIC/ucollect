#include "rng.h"

#include <assert.h>

struct rng_seed rng_seed_init(uint64_t seed) {
	struct rng_seed result;
	/*
	 * Since people tend to use quite small numbers and no
	 * number in the seed may be zero, we split the bits to
	 * even and odd, then interleave them to form the smaller
	 * number (we could shift them to the right one by one,
	 * but that would be more work).
	 */
	uint64_t even = seed & 0x5555555555555555LLU;
	uint64_t odd = seed & 0xAAAAAAAAAAAAAAAALLU;
	result.low = (even & 0x00000000FFFFFFFFLU) | ((even & 0xFFFFFFFF00000000LLU) >> 31);
	result.high = (odd & 0x00000000FFFFFFFFLU) | ((odd & 0xFFFFFFFF00000000LLU) >> 33);
	assert (result.low && result.high);
	return result;
}

uint32_t rng_get(struct rng_seed *seed) {
	seed->low = 36969 * (seed->low & 0xFFFF) + (seed->low >> 16);
	seed->high = 18000 * (seed->high & 0xFFFF) + (seed->high >> 16);
	return (seed->high << 16) + seed->low;
}

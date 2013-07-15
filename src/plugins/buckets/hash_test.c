#include "hash.h"

#include "../../core/mem_pool.h"
#include "../../core/util.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>

/*
 * A simple test to see the hash function in hash.h acts sanely.
 * We generate some random data for the hash function. Then we try
 * to hash all 4G possible 32bit values into 4G different buckets.
 * Then count how many buckets are empty and what is the biggest
 * size of a bucket.
 *
 * WARNING: This needs more than 4G of memory. Run somewhere with
 * lot of memory.
 */
int main(int argc, const char *argv[]) {
	(void) argc;
	(void) argv;
	struct mem_pool *pool = mem_pool_create("Pool");
	ulog(LLOG_WARN, "Going to allocate A LOT of memory. Last few seconds to quit before I swap your computer to death!\n");
	sleep(5);
	ulog(LLOG_DEBUG, "Generating random data for hash\n");
	const uint32_t *random_data = gen_hash_data(1234567891234LLU, 1, 256 * 4, pool);
	ulog(LLOG_DEBUG, "Preparing counters\n");
	uint8_t *counters = mem_pool_alloc(pool, 0x100000000LLU);
	memset(counters, 0, 0x100000000LLU);
	ulog(LLOG_DEBUG, "Hashing...\n");
	// Using larger data type, so we know when to stop
	for (uint64_t i = 0; i < 0x100000000LLU; i ++) {
		if ((i % 100000000) == 0)
			ulog(LLOG_DEBUG_VERBOSE, "%u done\n", (unsigned) i);
		uint32_t key = i;
		uint32_t value = hash((const uint8_t *) &key, 4, random_data);
		counters[value] ++;
	}
	ulog(LLOG_DEBUG, "Examining results\n");
	uint8_t max = 0;
	size_t zero_count = 0;
	size_t histogram[256];
	memset(histogram, 0, sizeof histogram);
	for (uint64_t i = 0; i < 0x100000000LLU; i ++) {
		if (counters[i] == 0)
			zero_count ++;
		if (counters[i] > max)
			max = counters[i];
		histogram[counters[i]] ++;
	}
	ulog(LLOG_INFO, "There are %zu empty buckets (%u%%) and the maximal size is %hhu\n", zero_count, (unsigned) (zero_count * 100LLU / 0x100000000LLU), max);
	for (uint64_t i = 0; i < 0x100000000LLU; i ++)
		if (counters[i] == max)
			ulog(LLOG_INFO, "Max at position %u\n", (unsigned) i);
	ulog(LLOG_INFO, "Histogram:\n");
	for (size_t i = 0; i < 256; i ++)
		fprintf(stderr, "%3zu: %zu\n", i, histogram[i]);
	return 0;
}

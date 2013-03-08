#ifndef UCOLLECT_BUCKETS_CRITERIA_H
#define UCOLLECT_BUCKETS_CRITERIA_H

#include <stddef.h>
#include <stdint.h>

struct mem_pool;
struct packet_info;

struct criterion_def {
	size_t key_size;
	/*
	 * A function to extract the key that we hash by. The packet is already
	 * the one to examine (so the caller shall traverse the list of next
	 * pointers in case of tunnels are used.
	 *
	 * It shall return either NULL, in case the packet doesn't contain
	 * corresponding key (eg. it is of different protocol), or a pointer
	 * to key_size bytes of the key. If the key is variable length,
	 * the whole length of key_size must be allocated and padded with
	 * constant values (zeroes, for example).
	 *
	 * The data may reside directly in the packet, or they can be allocated
	 * from the pool.
	 */
	const uint8_t *(*extract_key)(const struct packet_info *packet, struct mem_pool *tmp_pool);
	char name; // Name as denoted in the config
};

extern struct criterion_def criteria[];

#endif

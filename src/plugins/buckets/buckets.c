/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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
#include "criteria.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/uplink.h"
#include "../../core/util.h"
#include "../../core/loop.h"
#include "../../core/packet.h"
#include "../../core/trie.h"

#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

// A double-linked list to store the keys we work with atm.
struct key_candidate {
	struct key_candidate *next, *prev;
	const uint8_t *key;
};

struct key_candidates {
	struct key_candidate *head, *tail;
	size_t count;
};

#define LIST_NODE struct key_candidate
#define LIST_BASE struct key_candidates
#define LIST_PREV prev
#define LIST_COUNT count
#define LIST_NAME(X) key_candidates_##X
#define LIST_WANT_LFOR
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_REMOVE
#include "../../core/link_list.h"

struct criterion {
	struct trie **trie; // One trie for each bucket
	uint32_t *counts; // hash_count lines of bucket_count sizes
	uint32_t key_count; // Total number of different keys
	uint32_t packet_count; // Total number of keys. For consistency check.
	bool overflow; // Did it overflow (too many different keys?)
};

struct generation {
	struct mem_pool *pool; // Pool where the keys will be allocated from
	struct criterion *criteria;
	uint64_t timestamp;
	bool active; // Was it used already?
};

struct user_data {
	size_t bucket_count; // Number of buckets per hash
	size_t hash_count; // Count of different hashes
	size_t hash_line_size; // Number of bytes in hash_data per hash.
	size_t history_size; // How many old snapshots we keep, for the server to ask details about
	size_t max_key_count; // Maximum number of unique keys stored per generation and criterion.
	size_t max_timeslots; // Maximum number of timeslots in the current hash counts
	size_t biggest_timeslot; // The biggest used time slot
	uint64_t timeslot_start; // The time of start of the first timeslot
	uint32_t time_granularity; // Number of milliseconds per one timeslot
	uint32_t config_version;
	bool initialized; // Were we initialized already by the server?
	size_t criteria_count; // Count of criteria hashed
	struct criterion_def **criteria;
	const uint32_t *hash_data; // Random data used for hashing
	size_t current_generation;
	struct generation *generations; // One more than history_size, for the current one
};

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.initialized = false
	};
	uplink_plugin_send_message(context, "C", 1);
}

static void connected(struct context *context) {
	/*
	 * Ask for configuration on connect.
	 *
	 * Even if we are already configured, because it might have changed while we were
	 * gone.
	 */
	uplink_plugin_send_message(context, "C", 1);
	struct user_data *u = context->user_data;
	if (u->initialized) {
		for (size_t i = 0; i <= u->history_size; i ++)
			// Reset activity. We may have been away for a long time.
			u->generations[i].active = false;
	}
}

/*
 * Don't change the order. This is the header as seen on the network.
 * Note there should be no padding here except for the end anyway.
 */
struct config_header {
	uint64_t seed;
	uint64_t timestamp;
	uint32_t bucket_count;
	uint32_t hash_count;
	uint32_t criteria_count;
	uint32_t history_size;
	uint32_t config_version;
	uint32_t max_key_count;
	uint32_t max_timeslots;
	uint32_t time_granularity;
	char criteria[];
} __attribute__((packed));

static void generation_activate(struct user_data *u, size_t generation, uint64_t timestamp, uint64_t loop_now) {
	struct generation *g = &u->generations[generation];
	mem_pool_reset(g->pool);
	for (size_t i = 0; i < u->criteria_count; i ++) {
		// Reset the lists and the counts
		g->criteria[i].key_count = 0;
		g->criteria[i].packet_count = 0;
		g->criteria[i].overflow = false;
		memset(g->criteria[i].counts, 0, u->bucket_count * u->hash_count * u->max_timeslots * sizeof *g->criteria[i].counts);
		for (size_t j = 0; j < u->bucket_count; j ++)
			g->criteria[i].trie[j] = trie_alloc(g->pool);
	}
	g->timestamp = timestamp;
	g->active = true;
	u->current_generation = generation;
	u->timeslot_start = loop_now;
	u->biggest_timeslot = 0;
}

static void configure(struct context *context, const uint8_t *data, size_t length) {
	// We copy the data to make sure they are aligned properly.
	struct config_header *header = mem_pool_alloc(context->temp_pool, length);
	sanity(length >= sizeof *header, "The message is too short to contain bucket configuration header, only %zu bytes (%zu needed)\n", length, sizeof *header);
	memcpy(header, data, length);
	// Extract the elements of the header
	struct user_data *u = context->user_data;
	if (u->initialized) {
		if (u->config_version != ntohl(header->config_version)) {
			// We can't reload configuration, so we reinitialize the whole plugin.
			loop_plugin_reinit(context);
		} else
			return; // The config is loaded and is the same. Don't configure anything.
	}
	u->bucket_count = ntohl(header->bucket_count);
	u->hash_count = ntohl(header->hash_count);
	u->criteria_count = ntohl(header->criteria_count);
	size_t needed = sizeof *header + u->criteria_count * sizeof header->criteria[0];
	sanity(length >= needed, "The message is too short to contain bucket configuration, only %zu bytes (%zu needed)\n", length, needed);
	u->history_size = ntohl(header->history_size);
	u->config_version = ntohl(header->config_version);
	u->max_key_count = htonl(header->max_key_count);
	u->max_timeslots = htonl(header->max_timeslots);
	u->time_granularity = htonl(header->time_granularity);
	u->criteria = mem_pool_alloc(context->permanent_pool, u->criteria_count * sizeof *u->criteria);
	// Find the criteria to hash by
	size_t max_keysize = 0;
	for (size_t i = 0; i < u->criteria_count; i ++) {
		bool found = false;
		for (size_t j = 0; criteria[j].name; j ++)
			if (criteria[j].name == header->criteria[i]) {
				found = true;
				u->criteria[i] = &criteria[j];
				if (criteria[j].key_size > max_keysize)
					max_keysize = criteria[j].key_size;
			}
		sanity(found, "Bucket criterion of name '%c' not known\n", header->criteria[i]);
	}
	// Generate the random hash data
	u->hash_line_size = 256 * max_keysize;
	u->hash_data = gen_hash_data(be64toh(header->seed), u->hash_count, u->hash_line_size, context->permanent_pool);
	// Make room for the generations, hash counts and gathered keys
	u->generations = mem_pool_alloc(context->permanent_pool, (1 + u->history_size) * sizeof *u->generations);
	for (size_t i = 0; i <= u->history_size; i ++) {
		struct generation *g = &u->generations[i];
		*g = (struct generation) {
			.pool = loop_pool_create(context->loop, context, mem_pool_printf(context->temp_pool, "Generation %zu", i)),
			.criteria = mem_pool_alloc(context->permanent_pool, u->criteria_count * sizeof *g->criteria)
		};
		for (size_t j = 0; j < u->criteria_count; j ++)
			g->criteria[j] = (struct criterion) {
				// Single line for the keys
				.trie = mem_pool_alloc(context->permanent_pool, u->bucket_count * sizeof *g->criteria[j].trie),
				// hash_count lines for the hashed counts
				.counts = mem_pool_alloc(context->permanent_pool, u->bucket_count * u->hash_count * u->max_timeslots * sizeof *g->criteria[j].counts)
			};
			// We don't care about the values in newly-allocated data. We reset it at the start of generation
	}
	generation_activate(u, 0, be64toh(header->timestamp), loop_now(context->loop));
	sanity(u->criteria_count && u->hash_count && u->bucket_count, "A zero-sized bucket configuration received\n");
	ulog(LLOG_INFO, "Received bucket information version %u (%u buckets, %u hashes)\n", (unsigned) u->config_version, (unsigned) u->bucket_count, (unsigned) u->hash_count);
	u->initialized = true;
}

// The data of one generation, as sent on the wire.
struct generation_data {
	// Padding to align the rest. Skip on send.
	uint8_t padding[sizeof(uint64_t) - 1];
	char code; // Send from here onwards
	uint64_t timestamp;
	uint32_t config_version;
	uint32_t timeslots; // Number of time slots. May be 0 in case of overflow ("aborted")
	uint8_t data[];
} __attribute__((packed));

// Part of the generation_data, placed in the data[] element.
struct criterion_data {
	uint32_t overflow; // Could be bool, but it would mess alignment
	uint32_t counts[];
} __attribute__((packed));

static void provide_generation(struct context *context, const uint8_t *data, size_t length) {
	struct user_data *u = context->user_data;
	// Read the new timestamp
	uint64_t timestamp;
	sanity(length == sizeof timestamp, "Wrong size of the bucket generation timestamp (%zu vs %zu)\n", length, sizeof timestamp);
	memcpy(&timestamp, data, length); // Copy, to ensure correct alignment
	timestamp = be64toh(timestamp);
	ulog(LLOG_DEBUG, "Old generation is %zu, new %zu\n", (size_t) u->generations[u->current_generation].timestamp, (size_t) timestamp);
	// Compute the size of the message to send
	bool global_overflow = false;
	if (++ u->biggest_timeslot > u->max_timeslots) {
		u->biggest_timeslot = 0;
		global_overflow = true;
	}
	size_t criterion_size = sizeof(struct criterion_data) + u->hash_count * u->bucket_count * u->biggest_timeslot * sizeof(uint32_t);
	struct generation_data *msg = mem_pool_alloc(context->temp_pool, sizeof *msg + criterion_size * u->criteria_count);
	struct generation *g = &u->generations[u->current_generation];
	// Build the message
	msg->code = 'G';
	msg->timestamp = htobe64(g->timestamp);
	msg->config_version = htonl(u->config_version);
	msg->timeslots = htonl(u->biggest_timeslot);
	for (size_t i = 0; i < u->criteria_count; i ++) {
		struct criterion *src = &g->criteria[i];
		struct criterion_data *dst = (struct criterion_data *) &msg->data[i * criterion_size];
		dst->overflow = htonl(src->overflow || global_overflow);
		size_t total_count = 0;
		for (size_t j = 0; j < u->hash_count * u->bucket_count * u->biggest_timeslot; j ++) {
			dst->counts[j] = htonl(src->counts[j]);
			total_count += src->counts[j];
		}
		// Every packet should be once in each hash
		assert(global_overflow || total_count == src->packet_count * u->hash_count);
	}
	// Send it (skip the padding)
	uplink_plugin_send_message(context, &msg->code, sizeof *msg + criterion_size * u->criteria_count - sizeof msg->padding);
	size_t next_generation = u->current_generation + 1;
	next_generation %= (u->history_size + 1);
	generation_activate(u, next_generation, timestamp, loop_now(context->loop));
}

// A request to provide some filtered keys by the server
struct key_request {
	uint64_t generation_timestamp; // For finding the correct generation
	uint32_t req_id; // Just request ID to be sent back
	uint32_t criterion;
	uint32_t key_indices[];
} __attribute__((packed));

// An answer for key request
struct key_answer {
	char code; // Will be set to 'K'
	uint32_t req_id; // Copied from key_request, without a change
	uint8_t data[]; // The keys to be sent
} __attribute__((packed));

struct extract_data {
	struct key_candidates *candidates;
	struct mem_pool *pool;
};

static void get_key(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	(void)data;
	struct extract_data *d = userdata;
	struct key_candidate *new = key_candidates_append_pool(d->candidates, d->pool);
	uint8_t *key_data = mem_pool_alloc(d->pool, key_size);
	new->key = key_data;
	memcpy(key_data, key, key_size);
}

static struct key_candidates *scan_keys(uint32_t *indices, uint32_t length, size_t criterion, struct user_data *u, struct generation *g, struct mem_pool *pool) {
	sanity(length, "The index count is missing in the bucket keys request\n");
	uint32_t index_count = indices[0];
	length --;
	sanity(length >= index_count, "There are not enough indices in the bucket keys request, expected %u, but only %u found\n", (unsigned)length, (unsigned)index_count);
	indices ++;
	struct key_candidates *candidates = mem_pool_alloc(pool, sizeof *candidates);
	*candidates = (struct key_candidates) { .count = 0 };
	size_t key_size = u->criteria[criterion]->key_size;
	for (size_t i = 0; i < index_count; i ++) {
		sanity(indices[i] < u->bucket_count, "Bucket index out of bounds (%u vs %u)\n", (unsigned)indices[i], (unsigned)u->bucket_count);
		trie_walk(g->criteria[criterion].trie[indices[i]], get_key, &(struct extract_data) { .candidates = candidates, .pool = pool }, pool);
	}
	// Iterate the other levels and remove keys not passing the filter of indices
	for (size_t i = 1; i < u->hash_count; i ++) {
		// Move to the next group of indices
		indices += index_count;
		length -= index_count;
		sanity(length, "Run out of all the bucket indices before hash %zu\n", i);
		index_count = *indices;
		length --;
		indices ++;
		sanity(length >= index_count, "Not enough bucket indices for hash %zu - need %u, but only %u found\n", i, (unsigned)index_count, (unsigned)length);
		// Not using LFOR here, we need to manipulate the variable in the process
		struct key_candidate *candidate = candidates->head;
		while (candidate) {
			uint32_t h = hash(candidate->key, key_size, u->hash_data + i * u->hash_line_size);
			h %= u->bucket_count;
			struct key_candidate *to_del = candidate;
			for (size_t j = 0; j < index_count; j ++)
				if (indices[j] == h) {
					// This one is in a bucket we want
					to_del = NULL;
					break;
				}
			candidate = candidate->next; // Move to the next before we potentially remove it
			if (to_del)
				key_candidates_remove(candidates, to_del);
		}
	}
	sanity(length == index_count, "Extra %u bucket indices\n", (unsigned)(length - index_count)); // All indices eaten
	return candidates;
}

static void provide_keys(struct context *context, const uint8_t *data, size_t length) {
	struct user_data *u = context->user_data;
	// No key index is split in half
	sanity((length - sizeof(struct key_request)) % sizeof(uint32_t) == 0, "Bucket index split\n");
	// Copy the data so it is properly aligned
	struct key_request *request = mem_pool_alloc(context->temp_pool, length);
	memcpy(request, data, length);
	// How many indices are thele?
	length -= sizeof(struct key_request);
	length /= sizeof(uint32_t);
	// Find the generation
	struct generation *g = NULL;
	// Walk the keys and convert them to local endians.
	for (size_t i = 0; i < length; i ++)
		request->key_indices[i] = ntohl(request->key_indices[i]);
	size_t criterion = ntohl(request->criterion);
	sanity(criterion < u->criteria_count, "Criterion out of bounds (%zu vs %zu)\n", criterion, u->criteria_count);
	uint64_t timestamp = be64toh(request->generation_timestamp);
	size_t key_size = u->criteria[criterion]->key_size;
	struct key_candidates *candidates = NULL;
	if (timestamp) {
		for (size_t i = 0; i <= u->history_size; i ++)
			if (u->generations[i].timestamp == timestamp) {
				g = &u->generations[i];
				break;
			}
		if (!g) {
			// Say we are missing this generation
			uint8_t *message = mem_pool_alloc(context->temp_pool, 1 + sizeof request->req_id);
			*message = 'M';
			memcpy(message + 1, &request->req_id, sizeof request->req_id);
			uplink_plugin_send_message(context, message, 1 + sizeof request->req_id);
			return;
		}
		candidates = scan_keys(request->key_indices, length, criterion, u, g, context->temp_pool);
	} else {
		candidates = mem_pool_alloc(context->temp_pool, sizeof *candidates);
		*candidates = (struct key_candidates) { .count = 0 };
		// 0 means all keys
		for (size_t i = 0; i <= u->history_size; i ++)
			if (u->generations[i].active && i != u->current_generation) {
				// Active generations, but not the one that is being filled right now (the server may not be asking about that anyway)
				struct key_candidates *partial = scan_keys(request->key_indices, length, criterion, u, &u->generations[i], context->temp_pool);
				// Take the new linklist apart and put the yet nonexistent to the real one
				while (partial->head) {
					struct key_candidate *can = partial->head;
					key_candidates_remove(partial, can);
					bool found = false;
					LFOR(key_candidates, candidate, candidates)
						if (memcmp(candidate->key, can->key, key_size) == 0) {
							found = true;
							break;
						}
					if (!found)
						key_candidates_insert_after(candidates, can, candidates->tail);
				}
			}
	}
	// Build the answer - just copy all the passed keys to the result
	size_t answer_length = sizeof(struct key_answer) + key_size * candidates->count;
	struct key_answer *answer = mem_pool_alloc(context->temp_pool, answer_length);
	answer->code = 'K';
	// Copy the request id. By memcpy, since answer doesn't have to be aligned
	memcpy(&answer->req_id, &request->req_id, sizeof answer->req_id);
	size_t index = 0;
	LFOR(key_candidates, candidate, candidates)
		memcpy(answer->data + index ++ * key_size, candidate->key, key_size);
	uplink_plugin_send_message(context, answer, answer_length);
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	sanity(length, "Empty message routed to the buckets plugin\n");
	switch (*data) {
		case 'C': // Good, we got configuration
			configure(context, data + 1, length - 1);
			return;
		case 'G': // We are asked to send the current generation and start a new one
			if (context->user_data->initialized) {
				ulog(LLOG_DEBUG, "Asked for generation data\n");
				provide_generation(context, data + 1, length - 1);
			} else {
				/*
				 * It could probably hapen in rare race condition when we connect
				 * and directly get a request for data before we even get the
				 * configuration. This is because the server just broadcasts the
				 * request without tracking who already asked for configuration.
				 */
				ulog(LLOG_WARN, "Asked for generation data, but not initialized yet.\n");
				// Ignore it, we have nothing.
			}
			return;
		case 'K': // Send keys
			sanity(context->user_data->initialized, "Asked to send keys before initialization\n"); // The server should track who it asks
			provide_keys(context, data + 1, length - 1);
			return;
		default:
			ulog(LLOG_WARN, "Unknown buckets request %hhu/%c\n", *data, (char) *data);
			return;
	}
}

static void packet(struct context *context, const struct packet_info *packet) {
	struct user_data *u = context->user_data;
	if (!u->initialized)
		return; // No config yet, ignore the packet
	struct generation *g = &u->generations[u->current_generation];
	// Get the real packet, if it is in some tunnel
	while (packet->next)
		packet = packet->next;
	if (packet->layer != 'I')
		return; // Not an IP packet. Ignore.
	// Into which timeslot does the packet belong?
	size_t slot = (loop_now(context->loop) - u->timeslot_start) / u->time_granularity;
	if (slot < u->biggest_timeslot)
		ulog(LLOG_WARN, "Time went backwards?\n");
	else if (slot > u->biggest_timeslot)
		u->biggest_timeslot = slot;
	if (u->biggest_timeslot >= u->max_timeslots)
		// Nobody asked for data for way too long. The data will be unusable anyway..
		return;
	for (size_t i = 0; i < u->criteria_count; i ++) {
		// Extract the key first
		const uint8_t *key = u->criteria[i]->extract_key(packet, context->temp_pool);
		size_t length = u->criteria[i]->key_size;
		if (!key)
			continue; // This criteria is not applicable to the packet
		g->criteria[i].packet_count ++;
		// Hash it by each hashing function we have and increment the corresponding counts
		size_t key_index = 0;
		for (size_t j = 0; j < u->hash_count; j ++) {
			// Pick the correct hash_data to define the hash function
			uint32_t index = hash(key, length, u->hash_data + j * u->hash_line_size);
			// Increase the correct counter (on the correct line)
			index %= u->bucket_count;
			// We index the key hash table by the first hash
			if (j == 0)
				key_index = index;
			g->criteria[i].counts[u->bucket_count * u->hash_count * u->biggest_timeslot + j * u->bucket_count + index] ++;
		}
		// Store the key, if it is not there already
		if (g->criteria[i].overflow)
			continue; // Don't store more keys, so the memory doesn't overflow
		struct trie *t = g->criteria[i].trie[key_index];
		// We store the key in the key of trie, just by indexing it. No need to store more.
		trie_index(t, key, length);
		g->criteria[i].overflow = (trie_size(t) >= u->max_key_count);
	}
}

#ifdef STATIC
struct plugin *plugin_info_buckets(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Buckets",
		.init_callback = initialize,
		.uplink_connected_callback = connected,
		.uplink_data_callback = communicate,
		.packet_callback = packet,
		.version = 1
	};
	return &plugin;
}

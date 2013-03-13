#include "hash.h"
#include "criteria.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/uplink.h"
#include "../../core/util.h"
#include "../../core/loop.h"
#include "../../core/packet.h"

#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

// A list to store the keys in one generation
struct key {
	struct key *next;
	uint8_t data[];
};

struct keys {
	struct key *head, *tail;
};

#define LIST_NODE struct key
#define LIST_BASE struct keys
#define LIST_NAME(X) keys_##X
#define LIST_WANT_LFOR
#define LIST_WANT_INSERT_AFTER
#include "../../core/link_list.h"

// A double-linked list to store the keys we work with atm.
struct key_candidate {
	struct key_candidate *next, *prev;
	struct key *key;
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
	struct keys *hashed_keys; // Line corresponding to the first hash, storing the keys
	uint32_t *counts; // hash_count lines of bucket_count sizes
	uint32_t key_count; // Total number of different keys
	uint32_t packet_count; // Total number of keys. For consistency check.
	bool overflow; // Did it overflow (too many different keys?)
};

struct generation {
	struct mem_pool *pool; // Pool where the keys will be allocated from
	struct criterion *criteria;
	uint64_t timestamp;
};

struct user_data {
	size_t bucket_count; // Number of buckets per hash
	size_t hash_count; // Count of different hashes
	size_t hash_line_size; // Number of bytes in hash_data per hash.
	size_t history_size; // How many old snapshots we keep, for the server to ask details about
	size_t max_key_count; // Maximum number of unique keys stored per generation and criterion.
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
	 * If we weren't connected on our initialization, ask for the
	 * configuration now.
	 */
	if (!context->user_data->initialized)
		uplink_plugin_send_message(context, "C", 1);
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
	char criteria[];
} __attribute__((__packed__));

static void generation_activate(struct user_data *u, size_t generation, uint64_t timestamp) {
	struct generation *g = &u->generations[generation];
	for (size_t i = 0; i < u->criteria_count; i ++) {
		// Reset the lists and the counts
		g->criteria[i].key_count = 0;
		g->criteria[i].packet_count = 0;
		g->criteria[i].overflow = false;
		memset(g->criteria[i].hashed_keys, 0, u->bucket_count * sizeof *g->criteria[i].hashed_keys);
		memset(g->criteria[i].counts, 0, u->bucket_count * u->hash_count * sizeof *g->criteria[i].counts);
	}
	mem_pool_reset(g->pool);
	g->timestamp = timestamp;
	u->current_generation = generation;
}

static void configure(struct context *context, const uint8_t *data, size_t length) {
	// We copy the data to make sure they are aligned properly.
	struct config_header *header = mem_pool_alloc(context->temp_pool, length);
	assert(length >= sizeof *header);
	memcpy(header, data, length);
	// Extract the elements of the header
	struct user_data *u = context->user_data;
	u->bucket_count = ntohl(header->bucket_count);
	u->hash_count = ntohl(header->hash_count);
	u->criteria_count = ntohl(header->criteria_count);
	assert(length >= sizeof *header + u->criteria_count * sizeof header->criteria[0]);
	u->history_size = ntohl(header->history_size);
	u->config_version = ntohl(header->config_version);
	u->max_key_count = htonl(header->max_key_count);
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
		if (!found)
			die("Bucket riterion of name '%c' not known\n", header->criteria[i]);
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
				.hashed_keys = mem_pool_alloc(context->permanent_pool, u->bucket_count * sizeof *g->criteria[j].hashed_keys),
				// hash_count lines for the hashed counts
				.counts = mem_pool_alloc(context->permanent_pool, u->bucket_count * u->hash_count * sizeof *g->criteria[j].counts)
			};
			// We don't care about the values in newly-allocated data. We reset it at the start of generation
	}
	generation_activate(u, 0, be64toh(header->timestamp));
	assert(u->criteria_count && u->hash_count && u->bucket_count);
	ulog(LOG_INFO, "Received bucket information version %u (%u buckets, %u hashes)\n", (unsigned) u->config_version, (unsigned) u->bucket_count, (unsigned) u->hash_count);
	u->initialized = true;
}

// The data of one generation, as sent on the wire.
struct generation_data {
	// Padding to align the rest. Skip on send.
	uint8_t padding[sizeof(uint64_t) - 1];
	char code; // Send from here onwards
	uint64_t timestamp;
	uint32_t config_version;
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
	assert(length == sizeof timestamp);
	memcpy(&timestamp, data, length); // Copy, to ensure correct alignment
	timestamp = be64toh(timestamp);
	// Compute the size of the message to send
	size_t criterion_size = sizeof(struct criterion_data) + u->hash_count * u->bucket_count * sizeof(uint32_t);
	struct generation_data *msg = mem_pool_alloc(context->temp_pool, sizeof *msg + criterion_size * u->criteria_count);
	struct generation *g = &u->generations[u->current_generation];
	// Build the message
	msg->code = 'G';
	msg->timestamp = htobe64(g->timestamp);
	msg->config_version = htonl(u->config_version);
	for (size_t i = 0; i < u->criteria_count; i ++) {
		struct criterion *src = &g->criteria[i];
		struct criterion_data *dst = (struct criterion_data *) &msg->data[i * criterion_size];
		dst->overflow = htonl(src->overflow);
		size_t total_count = 0;
		for (size_t j = 0; j < u->hash_count * u->bucket_count; j ++) {
			dst->counts[j] = htonl(src->counts[j]);
			total_count += src->counts[j];
		}
		// Every packet should be once in each hash
		assert(total_count == src->packet_count * u->hash_count);
	}
	// Send it (skip the padding)
	uplink_plugin_send_message(context, &msg->code, sizeof *msg + criterion_size * u->criteria_count - sizeof msg->padding);
	size_t next_generation = u->current_generation + 1;
	next_generation %= (u->history_size + 1);
	generation_activate(u, next_generation, timestamp);
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

static void provide_keys(struct context *context, const uint8_t *data, size_t length) {
	struct user_data *u = context->user_data;
	// No key index is split in half
	assert((length - sizeof(struct key_request)) % sizeof(uint32_t) == 0);
	// Copy the data so it is properly aligned
	struct key_request *request = mem_pool_alloc(context->temp_pool, length);
	memcpy(request, data, length);
	// How many indices are thele?
	length -= sizeof(struct key_request);
	length /= sizeof(uint32_t);
	// Find the generation
	struct generation *g = NULL;
	for (size_t i = 0; i <= u->history_size; i ++)
		if (u->generations[i].timestamp == be64toh(request->generation_timestamp)) {
			g = &u->generations[i];
			break;
		}
	if (!g) {
		// Say we are missing this generation
		uplink_plugin_send_message(context, "M", 1);
		return;
	}
	// Walk the data and extract the keys for 0th hash function (directly stored)
	for (size_t i = 0; i < length; i ++)
		request->key_indices[i] = ntohl(request->key_indices[i]);
	assert(length);
	uint32_t index_count = request->key_indices[0];
	length --;
	assert(length >= index_count);
	uint32_t *indices = &request->key_indices[1];
	struct key_candidates candidates = { .count = 0 };
	size_t criterion = ntohl(request->criterion);
	assert(criterion < u->criteria_count);
	for (size_t i = 0; i < index_count; i ++)
		LFOR(keys, key, &g->criteria[criterion].hashed_keys[indices[i]])
			key_candidates_append_pool(&candidates, context->temp_pool)->key = key;
	// Iterate the other levels and remove keys not passing the filter of indices
	size_t key_size = u->criteria[criterion]->key_size;
	for (size_t i = 1; i < u->hash_count; i ++) {
		// Move to the next group of indices
		indices += index_count;
		length -= index_count;
		assert(length);
		index_count = *indices;
		length --;
		indices ++;
		assert(length >= index_count);
		// Not using LFOR here, we need to manipulate the variable in the process
		struct key_candidate *candidate = candidates.head;
		while (candidate) {
			uint32_t h = hash(candidate->key->data, key_size, u->hash_data + i * u->hash_line_size);
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
				key_candidates_remove(&candidates, to_del);
		}
	}
	assert(length == index_count); // All indices eaten
	// Build the answer - just copy all the passed keys to the result
	size_t answer_length = sizeof(struct key_answer) + key_size * candidates.count;
	struct key_answer *answer = mem_pool_alloc(context->temp_pool, answer_length);
	answer->code = 'K';
	// Copy the request id. By memcpy, since answer doesn't have to be aligned
	memcpy(&answer->req_id, &request->req_id, sizeof answer->req_id);
	size_t index = 0;
	LFOR(key_candidates, candidate, &candidates)
		memcpy(answer->data + index ++ * key_size, candidate->key->data, key_size);
	uplink_plugin_send_message(context, answer, answer_length);
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	assert(length);
	switch (*data) {
		case 'C': // Good, we got configuration
			if (context->user_data->initialized)
				// We already have one and we are not able to replace it. Try again.
				loop_plugin_reinit(context);
			configure(context, data + 1, length - 1);
			return;
		case 'G': // We are asked to send the current generation and start a new one
			if (context->user_data->initialized) {
				ulog(LOG_DEBUG, "Asked for generation data\n");
				provide_generation(context, data + 1, length - 1);
			} else {
				/*
				 * It could probably hapen in rare race condition when we connect
				 * and directly get a request for data before we even get the
				 * configuration. This is because the server just broadcasts the
				 * request without tracking who already asked for configuration.
				 */
				ulog(LOG_WARN, "Asked for generation data, but not initialized yet.\n");
				// Ignore it, we have nothing.
			}
			return;
		case 'K': // Send keys
			assert(context->user_data->initialized); // The server should track who it asks
			provide_keys(context, data + 1, length - 1);
			return;
		default:
			ulog(LOG_WARN, "Unknown buckets request %hhu/%c\n", *data, (char) *data);
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
			g->criteria[i].counts[j * u->bucket_count + index] ++;
		}
		// Store the key, if it is not there already
		if (g->criteria[i].overflow)
			continue; // Don't store more keys, so the memory doesn't overflow
		struct keys *keys = &g->criteria[i].hashed_keys[key_index];
		struct key *previous = NULL;
		bool found = false;
		LFOR(keys, stored, keys) {
			int cmp = memcmp(key, stored->data, length);
			if (cmp == 0)
				found = true; // No need to insert anything, already there
			else if (cmp < 0)
				break; // We found element larger than us. Insert before that one (after 'previous').
			// Else continue scanning the list, since we are still too large
			previous = stored; // Keep the previous, for possible insert.
		}
		if (!found) {
			g->criteria[i].overflow = (++ g->criteria[i].key_count == u->max_key_count);
			// Not stored there, store it.
			struct key *new = mem_pool_alloc(g->pool, sizeof *new + length);
			memcpy(new->data, key, length);
			keys_insert_after(keys, new, previous);
		}
	}
}

struct plugin *plugin_info(void) {
	static struct plugin plugin = {
		.name = "Buckets",
		.init_callback = initialize,
		.uplink_connected_callback = connected,
		.uplink_data_callback = communicate,
		.packet_callback = packet
	};
	return &plugin;
}

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
	uint32_t bucket_count;
	uint32_t hash_count;
	uint32_t criteria_count;
	uint32_t history_size;
	uint32_t config_version;
	uint32_t max_key_count;
	char criteria[];
} __attribute__((__packed__));

static void generation_activate(struct user_data *u, size_t generation) {
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
	generation_activate(u, 0);
	assert(u->criteria_count && u->hash_count && u->bucket_count);
	ulog(LOG_INFO, "Received bucket information version %u (%u buckets, %u hashes)\n", (unsigned) u->config_version, (unsigned) u->bucket_count, (unsigned) u->hash_count);
	u->initialized = true;
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	assert(length);
	switch (*data) {
		case 'C': // Good, we got configuration
			assert(!context->user_data->initialized);
			configure(context, data + 1, length - 1);
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
		size_t key_index;
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

struct plugin *plugin_info() {
	static struct plugin plugin = {
		.name = "Buckets",
		.init_callback = initialize,
		.uplink_connected_callback = connected,
		.uplink_data_callback = communicate,
		.packet_callback = packet
	};
	return &plugin;
}

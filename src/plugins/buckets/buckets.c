#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"

#include <stdbool.h>

struct user_data {
	size_t bucket_count; // Number of buckets per hash
	size_t hash_count; // Count of different hashes
	size_t criteria_count; // Count of criteria hashed
	size_t history_size; // How many old snapshots we keep, for the server to ask details about
	bool initialized; // Were we initialized already by the server?
};

void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.initialized = false
	};
}

struct plugin *plugin_info() {
	static struct plugin plugin = {
		.name = "Buckets",
		.init_callback = initialize
	};
	return &plugin;
}

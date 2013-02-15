#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"

struct user_data {
	size_t count;
	size_t count_v6;
	size_t count_v4;
	size_t count_in;
	size_t count_out;
};

static void packet_handle(struct context *context, const struct packet_info *info) {
	context->user_data->count ++;
	ulog(LOG_DEBUG_VERBOSE, "Packet counted (%zu total)\n", context->user_data->count);
}

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	// We would initialize with {} to zero everything, but iso C doesn't seem to allow that.
	*context->user_data = (struct user_data) {
		.count = 0
	};
}

struct plugin *plugin_info() {
	static struct plugin plugin = {
		.name = "Count",
		.packet_callback = packet_handle,
		.init_callback = initialize
	};
	return &plugin;
}

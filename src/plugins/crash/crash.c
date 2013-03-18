#include "../../core/plugin.h"
#include "../../core/loop.h"
#include "../../core/context.h"

#include <stdlib.h>

/*
 * WARNING: This is a testing plugin only. The only thing it does is to crash
 * after 2 seconds of runtime. It is not expected to be used in production.
 */

static void crash(struct context *context_unused, void *data_unused, size_t id_unused) {
	(void) context_unused;
	(void) data_unused;
	(void) id_unused;
	abort();
}

static void prepare_crash(struct context *context) {
	loop_timeout_add(context->loop, 2000, context, NULL, crash);
}

static void packet_crash(struct context *context_unused, const struct packet_info *info_unused) {
	(void) context_unused;
	(void) info_unused;
	abort();
}

static void data_crash(struct context *context_unused, const uint8_t *data_unused, size_t length_unused) {
	(void) context_unused;
	(void) data_unused;
	(void) length_unused;
	abort();
}

struct plugin *plugin_info(void) {
	static struct plugin plugin = {
		.name = "Crash",
		.uplink_data_callback = data_crash,
		.init_callback = prepare_crash,
		.packet_callback = packet_crash
	};
	return &plugin;
}

#include "../../core/plugin.h"

/*
 * WARNING: This is a testing plugin only. The only thing it does is to crash
 * after 2 seconds of runtime. It is not expected to be used in production.
 */

struct plugin *plugin_info(void) {
	static struct plugin plugin = {
		.name = "Crash",
	};
	return &plugin;
}

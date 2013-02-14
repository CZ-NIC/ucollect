#ifndef UCOLLECT_PLUGIN_H
#define UCOLLECT_PLUGIN_H

#include <stddef.h>

struct context;
struct packet_info;

typedef void (*packet_callback_t)(struct context *context, const struct packet_info *info);

struct plugin {
	const char *name;
	packet_callback_t packet_callback;
	void (*init_callback)(struct context *context);
	void (*finish_callback)(struct context *context);
};

#endif

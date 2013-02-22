#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"

#include <arpa/inet.h>

struct user_data {
	size_t count;
	size_t count_v6, count_v4;
	size_t count_in, count_out;
	size_t count_tcp, count_udp, count_icmp;
	size_t low_port_count;
	size_t size_in, size_out, size;
};

static void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *d = context->user_data;
	if (info->next) {
		// It's wrapper around some other real packet. We're not interested in the envelope.
		packet_handle(context, info->next);
		return;
	}
	d->count ++;
	d->size += info->length - info->hdr_length;
	switch (info->direction) {
		case DIR_IN:
			d->count_in ++;
			d->size_in += info->length - info->hdr_length;
			break;
		case DIR_OUT:
			d->count_out ++;
			d->size_out += info->length - info->hdr_length;
			break;
		default:;// Ignore others (and silence warning)
	}
	switch (info->ip_protocol) {
		case 4:
			d->count_v4 ++;
			break;
		case 6:
			d->count_v6 ++;
			break;
	}
	switch (info->app_protocol) {
		case 'T':
			d->count_tcp ++;
			break;
		case 'U':
			d->count_udp ++;
			break;
		case 'i':
		case 'I':
			d->count_icmp ++;
	}
	enum endpoint remote = remote_endpoint(info->direction);
	if (remote != END_COUNT && info->ports[remote] <= 1024 && info->ports[remote] != 0)
		d->low_port_count ++;
	ulog(LOG_DEBUG_VERBOSE,
"Statistics after received packet:\n"
"Total app data size:	%7zu\n"
"Size in:		%7zu\n"
"Size out:		%7zu\n"
"Total count:		%7zu\n"
"IPv6:			%7zu\n"
"IPv4:			%7zu\n"
"IN:			%7zu\n"
"OUT:			%7zu\n"
"TCP:			%7zu\n"
"UDP:			%7zu\n"
"ICMP:			%7zu\n"
"On low port:		%7zu\n"
		, d->size, d->size_in, d->size_out, d->count, d->count_v6, d->count_v4, d->count_in, d->count_out, d->count_tcp, d->count_udp, d->count_icmp, d->low_port_count);
}

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	// We would initialize with {} to zero everything, but iso C doesn't seem to allow that.
	*context->user_data = (struct user_data) {
		.count = 0
	};
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	// TODO: Error handling
	if (length != 1)
		return;
	switch (*data) {
		case 'D': {// Send and reset the data
			struct user_data *d = context->user_data;
			/*
			 * Since the structure is just bunch of items of the same type,
			 * we can look at it as an array. This allows us to convert
			 * it in an easier way. It is a slight abuse, but it should
			 * be legal according to the C standard (though it is probably
			 * fragile) and this plugin is more like a proof of concept
			 * anyway.
			 */
			size_t *items = (size_t *) d;
			size_t item_count = sizeof *d / sizeof *items;
			uint32_t message[item_count];
			for (size_t i = 0; i < item_count; i ++) {
				message[i] = htonl(items[i]);
				items[i] = 0;
			}
			uplink_plugin_send_message(context, message, sizeof message);
			break;
		}
	}
}

struct plugin *plugin_info() {
	static struct plugin plugin = {
		.name = "Count",
		.packet_callback = packet_handle,
		.init_callback = initialize,
		.uplink_data_callback = communicate
	};
	return &plugin;
}

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/loop.h"

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <endian.h>

enum selector {
	ANY,
	V4, V6,
	IN, OUT,
	TCP, UDP, ICMP,
	LOW_PORT,
	SYN_FLAG, FIN_FLAG, SYN_ACK_FLAG, ACK_FLAG, PUSH_FLAG,
	SERVER,
	MAX
};

// This should get _no_ paddings, on 32bit nor 64bit systems
struct user_data {
	uint64_t timestamp;
	struct {
		uint32_t count;
		uint32_t size;
	} data[MAX];
};

static void update(struct user_data *d, const struct packet_info *info, enum selector selector) {
	assert(selector < MAX);
	d->data[selector].count ++;
	d->data[selector].size += info->length - info->hdr_length;
}

static void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *d = context->user_data;
	if (info->next) {
		// It's wrapper around some other real packet. We're not interested in the envelope.
		packet_handle(context, info->next);
		return;
	}
	update(d, info, ANY);
	switch (info->direction) {
		case DIR_IN:
			update(d, info, IN);
			break;
		case DIR_OUT:
			update(d, info, OUT);
			break;
		default:;// Ignore others (and silence warning)
	}
	switch (info->ip_protocol) {
		case 4:
			update(d, info, V4);
			break;
		case 6:
			update(d, info, V6);
			break;
	}
	switch (info->app_protocol) {
		case 'T':
			update(d, info, TCP);
			if (info->tcp_flags & TCP_SYN)
				update(d, info, SYN_FLAG);
			if (info->tcp_flags & TCP_FIN)
				update(d, info, FIN_FLAG);
			if ((info->tcp_flags & TCP_FIN) && (info->tcp_flags & TCP_FIN))
				update(d, info, SYN_ACK_FLAG);
			if (info->tcp_flags & TCP_ACK)
				update(d, info, ACK_FLAG);
			if (info->tcp_flags & PUSH_FLAG)
				update(d, info, PUSH_FLAG);
			break;
		case 'U':
			update(d, info, UDP);
			break;
		case 'i':
		case 'I':
			update(d, info, ICMP);
	}
	enum endpoint remote = remote_endpoint(info->direction);
	if (remote != END_COUNT) {
		if (info->ports[remote] <= 1024 && info->ports[remote] != 0)
			update(d, info, LOW_PORT);
		// TODO: Make the remote server configurable.
		static const uint8_t address[] = { 217, 31, 192, 10 };
		// Communication with the server. Hardcoded for now. Exclude ssh (at least for current development)
		if (info->ip_protocol == 4 && memcmp(address, info->addresses[remote], 4) == 0 && info->ports[remote] != 22)
			update(d, info, SERVER);
	}
}

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	// We would initialize with {} to zero everything, but iso C doesn't seem to allow that.
	*context->user_data = (struct user_data) {
		.timestamp = 0
	};
}

struct encoded {
	uint64_t timestamp;
	uint32_t if_count;
	uint32_t data[];
};

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	if (length != sizeof(uint64_t))
		die("Invalid request from upstream to plugin count, size %zu\n", length);
	struct user_data *u = context->user_data;
	// Extract timestamp for the next interval
	uint64_t timestamp;
	memcpy(&timestamp, data, length);
	timestamp = be64toh(timestamp);
	// Generate capture statistics
	size_t *stats = loop_pcap_stats(context);
	// Get enough space to encode the result
	size_t enc_len = 3 * *stats + 2 * MAX;
	struct encoded *encoded;
	size_t enc_size = sizeof *encoded + enc_len * sizeof *encoded->data;
	encoded = mem_pool_alloc(context->temp_pool, enc_size);
	encoded->timestamp = htobe64(u->timestamp);
	// Encode the statistics
	encoded->if_count = htonl(*stats);
	for (size_t i = 0; i < 3 * *stats; i ++)
		encoded->data[i] = htonl(stats[i + 1]);
	// Encode the counts & sizes
	size_t offset = 3 * *stats;
	for (size_t i = 0; i < MAX; i ++) {
		encoded->data[2 * i + offset] = htonl(u->data[i].count);
		encoded->data[2 * i + offset + 1] = htonl(u->data[i].size);
	}
	// Send the message
	uplink_plugin_send_message(context, encoded, enc_size);
	// Reset the statistics
	*u = (struct user_data) {
		.timestamp = timestamp
		// The rest are zeroes
	};
}

#ifdef STATIC
struct plugin *plugin_info_count(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Count",
		.packet_callback = packet_handle,
		.init_callback = initialize,
		.uplink_data_callback = communicate
	};
	return &plugin;
}

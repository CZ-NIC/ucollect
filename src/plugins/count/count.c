/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC

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

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/loop.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
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

static void update(struct user_data *d, enum selector selector, size_t size) {
	assert(selector < MAX);
	d->data[selector].count ++;
	d->data[selector].size += size;
}

static void packet_handle_internal(struct context *context, const struct packet_info *info, size_t size) {
	struct user_data *d = context->user_data;
	if (info->next) {
		// It's wrapper around some other real packet. We're not interested in the envelope.
		packet_handle_internal(context, info->next, size);
		return;
	}
	update(d, ANY, size);
	ulog(LLOG_DEBUG_VERBOSE, "New packet, currently %zu/%zu\n", (size_t) d->data[ANY].count, (size_t) d->data[ANY].size);
	switch (info->direction) {
		case DIR_IN:
			update(d, IN, size);
			break;
		case DIR_OUT:
			update(d, OUT, size);
			break;
		default:;// Ignore others (and silence warning)
	}
	if (info->layer != 'I')
		// Not an IP packet. Don't try to interpret it as so.
		return;
	switch (info->ip_protocol) {
		case 4:
			update(d, V4, size);
			break;
		case 6:
			update(d, V6, size);
			break;
	}
	switch (info->app_protocol) {
		case 'T':
			update(d, TCP, size);
			if (info->tcp_flags & TCP_SYN)
				update(d, SYN_FLAG, size);
			if (info->tcp_flags & TCP_FIN)
				update(d, FIN_FLAG, size);
			if ((info->tcp_flags & TCP_ACK) && (info->tcp_flags & TCP_SYN))
				update(d, SYN_ACK_FLAG, size);
			if (info->tcp_flags & TCP_ACK)
				update(d, ACK_FLAG, size);
			if (info->tcp_flags & PUSH_FLAG)
				update(d, PUSH_FLAG, size);
			break;
		case 'U':
			update(d, UDP, size);
			break;
		case 'i':
		case 'I':
			update(d, ICMP, size);
	}
	enum endpoint remote = remote_endpoint(info->direction);
	if (remote != END_COUNT) {
		if (info->ports[remote] <= 1024 && info->ports[remote] != 0)
			update(d, LOW_PORT, size);
		for (struct addrinfo *addr = uplink_addrinfo(context->uplink); addr; addr = addr->ai_next) {
			size_t size = 0;
			void *pos = NULL;
			switch (addr->ai_family) {
				case AF_INET:
					size = 4;
					pos = &((struct sockaddr_in *) addr->ai_addr)->sin_addr;
					break;
				case AF_INET6:
					size = 16;
					pos = &((struct sockaddr_in6 *) addr->ai_addr)->sin6_addr;
					break;
			}
			if (pos && size == info->addr_len && memcmp(pos, info->addresses[remote], size) == 0 && info->ports[remote] != 22) {
				// One of the addresses matched.
				update(d, SERVER, size);
				break; // Count it at most once, even if the address would be there more than once.
			}
		}
	}
}

static void packet_handle(struct context *context, const struct packet_info *info) {
	packet_handle_internal(context, info, info->length);
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
	size_t enc_size = sizeof encoded->timestamp + sizeof encoded->if_count + enc_len * sizeof *encoded->data;
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
		ulog(LLOG_DEBUG_VERBOSE, "Sending count value for %zu: %zu/%zu at offset %zu\n", i, (size_t) u->data[i].count, (size_t) u->data[i].size, offset + 2*i);
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

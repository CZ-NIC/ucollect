/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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
#include "../../core/util.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <assert.h>

struct request_v4 {
	uint32_t src_address;
	uint32_t dest_address;
	uint16_t port;
	uint64_t token;
} __attribute__((packed));

#define C(RESULT, FUNCTION) do { if ((RESULT) == -1) { ulog(LLOG_ERROR, "Spoofer failed at " FUNCTION ": %s\n", strerror(errno)); if (fd != -1) { close(fd); } return; } } while (0)

struct udp {
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t check;
} __attribute__((packed));

#define MLEN 192
#define MESSAGE "This is a testing packet from project Turris. More info at http://blackhole.turris.cz. Contact us at info@turris.cz if you have questions."
#define MAGIC 0x17ACEE43

struct packet_data {
	uint32_t magic;
	uint64_t token;
	bool spoofed;
	char message[MLEN];
} __attribute__((packed));

struct user_data {
	bool expected;
	struct packet_data expected_packet;
	struct request_v4 request;
};

static void init(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
}

/*
 * We send out the ordinary, non-spoofed packet first.
 *
 * Then we watch for it to go out and copy a lot of values out
 * from it, since it would be very complex to detect (reading routing
 * tables, etc).
 */
static void handle_request_v4(struct user_data *u, const struct request_v4 *request) {
	ulog(LLOG_DEBUG, "Sending non-spoofed packet\n");
	// Prepare a raw socket
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	C(fd, "UDP socket");
	// Prepare data for the packet
	struct packet_data packet = {
		.magic = htonl(MAGIC),
		.token = request->token, // Already in network byte order
	};
	strncpy(packet.message, MESSAGE, MLEN);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = request->port, // Already in network byte order
		.sin_addr.s_addr = request->dest_address // As well
	};
	C(sendto(fd, &packet, sizeof packet, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof addr), "Ordinary sendto failed");
	// Start looking for the packet
	u->expected = true;
	u->expected_packet = packet;
	u->request = *request;
	u->request.port = ntohs(u->request.port);
}

struct packet_raw {
	struct ethhdr eth;
	struct iphdr ip;
	struct udp udp;
	struct packet_data data;
} __attribute__((packed));

struct packet_raw_tagged {
	struct ethhdr eth;
	uint16_t tag;
	uint16_t ethtype;
	struct iphdr ip;
	struct udp udp;
	struct packet_data data;
} __attribute__((packed));

static uint32_t ip_check(const void *data, size_t size) {
	assert(size % 2 == 0);
	size /= 2;
	const uint16_t *d = data;
	uint32_t sum = 0;
	while (size) {
		sum += ntohs(*d);
		d ++;
		size --;
	}
	return htons(0xFFFF - ((sum & 0xFFFF) + ((sum & 0xFFFF0000) >> 16)));
}

static void received(struct context *context, const struct packet_info *info) {
	struct user_data *u = context->user_data;
	if (!u->expected)
		return; // Not looking for a packet now.
	if (info->direction != DIR_OUT)
		return; // The packet we sent and are looking for went out
	const struct packet_info *ip = info;
	while (ip->next)
		ip = ip->next;
	if (ip->layer != 'I')
		return; // There's no IP at the end.
	if (ip->app_protocol != 'U')
		return; // Not UDP
	if (ip->ports[END_DST] != u->request.port)
		return; // Different destination port
	if (memcmp(ip->addresses[END_DST], &u->request.dest_address, sizeof u->request.dest_address) != 0)
		return; // Different address
	if (ip->length - ip->hdr_length != sizeof u->expected_packet)
		return; // Packet of a wrong length
	if (memcmp((const uint8_t *)ip->data + ip->hdr_length, &u->expected_packet, sizeof u->expected_packet) != 0)
		return; // The content of packet is different
	const struct packet_info *ether = info;
	// Find the ethernet layer, we need to copy the MAC addresses and possibly VLAN.
	while (ether->layer != 'E' && ether->next)
		ether = ether->next;
	if (ether->next != ip) {
		ulog(LLOG_WARN, "IP encapsulation in place, spoofing of packets not implemented in such case.\n");
		return;
	}
	ulog(LLOG_DEBUG, "Non-spoofed packet spotted on %s\n", info->interface);
	u->expected = false;
	struct packet_raw packet = {
		.eth = {
			.h_proto = htons(0x0800)
			// MAC addresses below
		},
		.ip = {
			.version = 4,
			.ihl = 5,
			.tot_len = htons(sizeof(struct ip) + sizeof(struct udp) + sizeof(struct packet_data)),
			.id = 0x0102,
			.frag_off = htons(IP_DF),
			.ttl = 64,
			.protocol = IPPROTO_UDP,
			.saddr = u->request.src_address,
			.daddr = u->request.dest_address
		},
		.udp = {
			.sport = htons(ip->ports[END_SRC]),
			.dport = htons(ip->ports[END_DST]),
			.len = htons(sizeof(struct udp) + sizeof(struct packet_data))
		},
		.data = u->expected_packet
	};
	packet.data.spoofed = true;
	packet.ip.check = ip_check(&packet.ip, sizeof packet.ip);
	memcpy(packet.eth.h_source, ether->addresses[END_SRC], ETH_ALEN);
	memcpy(packet.eth.h_dest, ether->addresses[END_DST], ETH_ALEN);
	const void *data = &packet;
	size_t size = sizeof packet;
	if (ether->vlan_tag) {
		// Insert the VLAN tag in the middle
		struct packet_raw_tagged *tagged = mem_pool_alloc(context->temp_pool, sizeof *tagged);
		*tagged = (struct packet_raw_tagged) {
			.eth = packet.eth,
			.tag = htons(ether->vlan_tag),
			.ethtype = packet.eth.h_proto,
			.ip = packet.ip,
			.udp = packet.udp,
			.data = packet.data
		};
		tagged->eth.h_proto = htons(0x8100);
		data = tagged;
		size = sizeof *tagged;
	}
	struct ifreq req;
	strncpy(req.ifr_name, info->interface, IFNAMSIZ);
	req.ifr_name[IFNAMSIZ - 1] = '\0';
	int fd = socket(AF_PACKET, SOCK_RAW, htons(0x0800));
	C(ioctl(fd, SIOCGIFINDEX, &req), "Get if index");
	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(0x0800),
		.sll_ifindex = req.ifr_ifindex
	};
	C(bind(fd, (struct sockaddr *)&addr, sizeof addr), "Bind");
	C(sendto(fd, data, size, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof addr), "Spoofed sendto");
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	(void)context;
	if (!length) {
		ulog(LLOG_ERROR, "No data for spoof plugin\n");
		return;
	}
	length --;
	switch (*data) {
		case '4':
			if (length < sizeof(struct request_v4)) {
				ulog(LLOG_ERROR, "Too short data for spoof v4 request, need %zu, have %zu\n", sizeof(struct request_v4), length);
				return;
			}
			struct request_v4 request;
			memcpy(&request, data + 1, sizeof request);
			handle_request_v4(context->user_data, &request);
			break;
		default:
			ulog(LLOG_ERROR, "Unknown spoof command %c\n", *data);
			return;
	}
}

#ifdef STATIC
struct plugin *plugin_info_spoof(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Spoof",
		.init_callback = init,
		.uplink_data_callback = communicate,
		.packet_callback = received,
		.version = 1
	};
	return &plugin;
}

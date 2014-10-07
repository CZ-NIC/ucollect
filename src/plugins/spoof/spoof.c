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

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>

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

struct packet_v4 {
	struct iphdr iphdr;
	struct udp udp;
	uint32_t magic;
	uint64_t token;
	bool spoofed;
	char message[MLEN];
} __attribute__((packed));

static void handle_request_v4(const struct request_v4 *request) {
	// Prepare a raw socket
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	C(fd, "socket");
	/*
	 * Prepare the packet. Note that the request already contains network-byte-order data,
	 * we didn't translate it to host byte order and therefore we don't have to translate
	 * back.
	 */
	struct packet_v4 packet = {
		.iphdr = {
			.version = 4,
			.ihl = 5,
			.ttl = 64,
			.protocol = IPPROTO_UDP,
			.saddr = request->src_address,
			.daddr = request->dest_address
		},
		.udp = {
			.sport = request->port,
			.dport = request->port,
			.len = htons(sizeof packet - sizeof packet.iphdr)
		},
		.magic = htonl(MAGIC),
		.token = request->token,
		.spoofed = true
	};
	strncpy(packet.message, MESSAGE, MLEN);
	// Construct the address for the packet
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(IPPROTO_UDP),
		.sin_addr.s_addr = request->dest_address
	};
	// Send it out
	C(sendto(fd, &packet, sizeof packet, 0, (struct sockaddr *)&addr, sizeof addr), "sendto spoofed");
	// Create the non-spoofed one and send it out too (0 address means to let the OS fill it in).
	packet.iphdr.saddr = 0;
	packet.spoofed = false;
	C(sendto(fd, &packet, sizeof packet, 0, (struct sockaddr *)&addr, sizeof addr), "sendto non-spoofed");
	close(fd);
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
			handle_request_v4(&request);
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
		.uplink_data_callback = communicate,
		.version = 1
	};
	return &plugin;
}

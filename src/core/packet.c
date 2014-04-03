/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "packet.h"
#include "mem_pool.h"
#include "util.h"

// These are for the IP header structs.
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <pcap/pcap.h>

#include <stdbool.h>
#include <string.h>

// UDP header is 4 2-byte words long
#define UDP_LENGTH 8
// All the sizes of headers are specified in 4-byte chunks
#define HEADER_SIZE_UNIT 4
// The offset resides in the high 4 bytes of the offset byte
#define OFFSET_MASK 0xf0
// The offset is in the high half of the offset byte, shift by 4 bits to get the actual number
#define OFFSET_SHIFT 4

/*
 * Both TCP and UDP have the same start, the ports. In case of TCP, we use the
 * data offset too (which should still be masked out), in UDP it may fall out
 * of the packet. But we won't access it, so it doesn't matter. Therefore we abuse
 * it to UDP too.
 */
struct tcp_ports {
	uint16_t sport;
	uint16_t dport;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t offset;
	uint8_t flags;
};

static void parse_internal(struct packet_info *packet, struct mem_pool *pool) {
	ulog(LLOG_DEBUG_VERBOSE, "Parse IP packet\n");
	packet->app_protocol_raw = 0xff;
	/*
	 * Try to put the packet into the form for an IP packet. We're lucky, the version field
	 * is on the same place for v6 as for v4, so it works.
	 */
	const struct iphdr *iphdr = packet->data;
	ulog(LLOG_DEBUG_VERBOSE, "Parsing packet of %zu bytes, version %i\n", packet->length, (int) iphdr->version);
	if (packet->length < sizeof *iphdr) {
		// Packet too short. Not IP therefore, bail out.
		packet->ip_protocol = 0;
		return;
	}
	packet->ip_protocol = iphdr->version;
	switch (packet->ip_protocol) {
		case 4:
			// Don't copy the addresses, just point inside the packet.
			packet->addresses[END_SRC] = &iphdr->saddr;
			packet->addresses[END_DST] = &iphdr->daddr;
			packet->addr_len = 4;
			// Temporary length, for further parsing (IP only).
			packet->hdr_length = HEADER_SIZE_UNIT * iphdr->ihl;
			packet->app_protocol_raw = iphdr->protocol;
			break;
		case 6: {
			// It's an IPv6 packet, put it into a v6 form instead.
			const struct ip6_hdr *ip6 = packet->data;
			if (packet->length < sizeof *ip6) {
				// It claims to be an IPv6 packet, but it's too short for that.
				packet->ip_protocol = 0;
				return;
			}
			packet->addresses[END_SRC] = &ip6->ip6_src.s6_addr;
			packet->addresses[END_DST] = &ip6->ip6_dst.s6_addr;
			packet->addr_len = 16;
			/*
			 * Temporary length, for further processing. Unlike IPv4, the
			 * header length is fixed.
			 */
			packet->hdr_length = sizeof *ip6;
			packet->app_protocol_raw = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
			break;
		}
		default: // Something else. Don't try to find TCP/UDP.
			return;
	}

	/*
	 * The start of the next header. Might be tcp, or something else (we abuse the structure
	 * for UDP too).
	 *
	 * In case it isn't UDP nor TCP, we don't use the structure, so it doesn't matter it points
	 * to something that makes no sense.
	 *
	 * As C doesn't allow adding an integer to a void pointer, we cast to pointer to unsigned char.
	 */
	const void *below_ip = (((const uint8_t *) packet->data) + packet->hdr_length);
	const struct tcp_ports *tcp_ports = below_ip;
	size_t length_rest = packet->length - packet->hdr_length;
	// Default protocol is unknown.
	packet->app_protocol = '?';
	switch (packet->app_protocol_raw) {
		// Just hardcode the numbers here for our use.
		case 1: // ICMP
			packet->app_protocol = 'i';
			return; // Not parsing further.
		case 4:  // Encapsulation of IPv4
		case 41: // And v6
			packet->app_protocol = packet->app_protocol_raw == 4 ? '4' : '6';
			ulog(LLOG_DEBUG_VERBOSE, "There's a IPv%c packet inside\n", packet->app_protocol);
			// Create a new structure for the packet and parse recursively
			struct packet_info *next = mem_pool_alloc(pool, sizeof *packet->next);
			packet->next = next;
			next->data = below_ip;
			next->length = length_rest;
			next->interface = packet->interface;
			next->direction = packet->direction;
			uc_parse_packet(next, pool, DLT_RAW);
			return; // And we're done (no ports here)
		case 6: // TCP
			if (length_rest < sizeof *tcp_ports)
				/*
				 * It claims to be TCP, but it's too short for that.
				 * Actually, even if it passes this check, it may be
				 * too short for TCP, but it's long enough for the
				 * info we want, so we won't crash. Likely, such broken
				 * packets won't even get to us, but who knows for
				 * sure.
				 */
				return;
			packet->app_protocol = 'T';
			packet->hdr_length += HEADER_SIZE_UNIT * ((tcp_ports->offset & OFFSET_MASK) >> OFFSET_SHIFT);
			packet->tcp_flags = tcp_ports->flags;
			break;
		case 17: // UDP
			packet->app_protocol = 'U';
			if (length_rest < UDP_LENGTH)
				// Too short for UDP
				return;
			packet->hdr_length += UDP_LENGTH;
			break;
		case 58: // IPv6 ICMP
			packet->app_protocol = 'I';
			return; // Not parsing further
		default:
			// Something unknown. Keep the '?'
			return;
	}
	// Extract the ports
	packet->ports[END_SRC] = ntohs(tcp_ports->sport);
	packet->ports[END_DST] = ntohs(tcp_ports->dport);
}

// Zero or reset the some fields according to other fields, if they don't make sense in that context.
static void postprocess(struct packet_info *packet) {
	ulog(LLOG_DEBUG_VERBOSE, "Postprocessing packet\n");
	bool ip_known = (packet->ip_protocol == 4 || packet->ip_protocol == 6);
	if (!ip_known) {
		memset(&packet->addresses, 0, sizeof packet->addresses);
		packet->addr_len = 0;
		packet->app_protocol = '\0';
	}
	bool has_ports = (packet->app_protocol == 'T' || packet->app_protocol == 'U');
	if (!has_ports) {
		memset(&packet->ports, 0, sizeof packet->ports);
		packet->hdr_length = 0;
	}
	bool is_encapsulation = (packet->app_protocol == '4' || packet->app_protocol == '6');
	if (!is_encapsulation) {
		if (packet->next)
			ulog(LLOG_DEBUG_VERBOSE, "Reseting next pointer, because the protocol is %c\n", packet->app_protocol);
		packet->next = NULL;
	}
	if (packet->app_protocol != 'T')
		packet->tcp_flags = 0;
}

static void parse_type(struct packet_info *packet, struct mem_pool *pool, const unsigned char *data) {
	uint16_t type = ntohs(*(uint16_t *) data);
	// VLAN tagging
	if (type == 0x8100) // IEEE 802.1q
		data += 4;
	if (type == 0x88a8) // IEEE 802.1ad
		data += 8;
	size_t skipped = data - (const unsigned char*) packet->data;
	if (skipped >= packet->length)
		return; // Give up. Short packet.
	type = ntohs(*(uint16_t *) data);
	ulog(LLOG_DEBUG_VERBOSE, "Ethernet type %04hX\n", type);
	// Skip over the type
	data += 2;
	// Prepare the packet below
	struct packet_info *next = mem_pool_alloc(pool, sizeof *packet->next);
	packet->next = NULL; // No packet yet, it might be something else than IP.
	(*next) = (struct packet_info) {
		.data = data,
		.length = packet->length - skipped,
		.interface = packet->interface,
		.direction = packet->direction,
		.layer = 'I',
		.app_protocol = '?'
	};
	if (type < 0x0800) // Length, not type, as per IEEE 802.3. Assume IP in the rest.
		goto IP;
	switch (type) {
		case 0x0800: // IPv4
		case 0x86DD: // IPv6
			IP:
			packet->app_protocol = 'I';
			// Parse the IP part
			uc_parse_packet(next, pool, DLT_RAW);
			// Put the packet in.
			packet->next = next;
			break;
		case 0x08035: // Reverse ARP
			packet->app_protocol = 'a';
			break;
		case 0x0806: // ARP
			packet->app_protocol = 'A';
			break;
		case 0x0842: // Wake On Lan
			packet->app_protocol = 'W';
			break;
		case 0x8137: // IPX (both)
		case 0x8138:
			packet->app_protocol = 'X';
			break;
		case 0x888E: // EAP (authentication)
			packet->app_protocol = 'E';
			break;
		case 0x8863: // PPPoE (all kinds of messages)
		case 0x8864:
			packet->app_protocol = 'P';
			break;
	}
}

static void parse_ethernet(struct packet_info *packet, struct mem_pool *pool) {
	ulog(LLOG_DEBUG_VERBOSE, "Parse ethernet\n");
	const unsigned char *data = packet->data;
	if (packet->length < 14)
		return;
	/*
	 * The ethernet frame defines that we should have the peramble and
	 * start of frame delimiter. But these are probably on the wire only,
	 * as it seems the 8 bytes are not in the data we got. Similarly, the
	 * frame check sequence/CRC is not present in the data.
	 */
	// Point out the addresses
	packet->addresses[END_DST] = data;
	data += 6;
	packet->addresses[END_SRC] = data;
	data += 6;
	packet->addr_len = 6;
	parse_type(packet, pool, data);
}

/*
 * The linux cooked capture. Slightly different than ethernet, but not that much.
 */
static void parse_cooked(struct packet_info *packet, struct mem_pool *pool) {
	const unsigned char *data = packet->data;
	if (packet->length < 16)
		return;
	//uint16_t ptype = ntohs(*(uint16_t *) data);
	data += 2;
	//uint16_t atype = ntohs(*(uint16_t *) data);
	data += 2;
	packet->addr_len = ntohs(*(uint16_t *) data);
	data += 2;
	packet->addresses[END_DST] = NULL;
	packet->addresses[END_SRC] = data;
	data += 8;
	parse_type(packet, pool, data);
}

void uc_parse_packet(struct packet_info *packet, struct mem_pool *pool, int datalink) {
	ulog(LLOG_DEBUG_VERBOSE, "Uc parse packet at %i\n", datalink);
	packet->layer_raw = datalink;
	switch (datalink) {
		case DLT_EN10MB: // Ethernet II
		case DLT_IEEE802: // The same format, but different signalling which we're not interested in.
			packet->layer = 'E';
			parse_ethernet(packet, pool);
			break;
		case DLT_RAW: // RAW IP (already parsed out, possibly)
			packet->layer = 'I';
			parse_internal(packet, pool);
			postprocess(packet);
			break;
		case DLT_LINUX_SLL: // Linux cooked capture
			packet->layer = 'S';
			parse_cooked(packet, pool);
			break;
		default:
			packet->layer = '?';
			break;
	}
}

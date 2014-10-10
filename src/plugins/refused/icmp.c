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

#include "icmp.h"

#include "../../core/packet.h"

#include <assert.h>
#include <netinet/ip.h>

struct header_v4 {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t unused;
	uint8_t iphdr[];
} __attribute__((packed));

struct ports {
	uint16_t source;
	uint16_t destination;
} __attribute__((packed));

char nak_parse(const struct packet_info *packet, size_t *addr_len, const uint8_t **addr, uint16_t *loc_port, uint16_t *dest_port) {
	assert(packet->layer == 'I');
	assert(packet->app_protocol == 'I' || packet->app_protocol == 'i');
	size_t data_len = packet->length - packet->hdr_length;
	const uint8_t *data = (const uint8_t *)packet->data + packet->hdr_length;
	if (packet->ip_protocol == 4) {
		if (packet->app_protocol != 'i')
			return '\0'; // ICMPv6 sent over IPv4?!
		if (data_len < sizeof(struct header_v4))
			return '\0'; // Too short to contain ICMP
		const struct header_v4 *header = (const struct header_v4 *) data;
		if (header->type != 3)
			return '\0'; // Some uninteresting ICMP type.
		const struct iphdr *ip = (const struct iphdr *)header->iphdr;
		if (data_len < sizeof *header + sizeof *ip)
			return '\0'; // We don't have the complete IP header here
		if (ip->version != 4)
			return '\0'; // Some strange mismatch.
		if ((ntohs(ip->frag_off) & IP_OFFMASK) != 0)
			return '\0'; // Fragmented packet inside.
		if (ip->protocol != 6)
			return '\0'; // Not TCP
		*addr_len = 4;
		*addr = (const uint8_t *)&ip->daddr; // The remote end is the destination, because the encapsulated packet is the one going out from us.
		if (data_len < sizeof *header + 4 * ip->ihl + 8)
			return '\0'; // We were promised to have 8 bytes of the TCP header, but they are not here
		data_len -= sizeof *header + 4 * ip->ihl;
		const struct ports *ports = (const struct ports *)(header->iphdr + 4 * ip->ihl);
		*loc_port = ntohs(ports->source);
		*dest_port = ntohs(ports->destination);
		switch (header->code) {
			case 0:
			case 6:
				return 'N';
			case 1:
			case 7:
				return 'H';
			case 3:
				return 'P';
			case 9:
			case 10:
			case 13:
				return 'A';
			default:
				return 'O';
		}
	} else if (packet->ip_protocol == 6) {

	}
	return '\0';
}

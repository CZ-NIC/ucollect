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
#include <netinet/ip6.h>

struct header {
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
	if (data_len < sizeof(struct header))
		return '\0'; // Too short to contain ICMP
	const struct header *header = (const struct header *)data;
	uint8_t expected = packet->app_protocol == 'i' ? 3 : 1;
	if (header->type != expected)
		return '\0'; // Some uninteresting ICMP type.
	const struct iphdr *ip = (const struct iphdr *)header->iphdr;
	if (data_len < sizeof *header + sizeof *ip)
		return '\0'; // We don't have the complete IP header here
	size_t ip_len;
	if (ip->version == 4) { // What version of IP is inside?
		if ((ntohs(ip->frag_off) & IP_OFFMASK) != 0)
			return '\0'; // Fragmented packet inside.
		if (ip->protocol != 6)
			return '\0'; // Not TCP
		*addr_len = 4;
		*addr = (const uint8_t *)&ip->daddr; // The remote end is the destination, because the encapsulated packet is the one going out from us.
		ip_len = 4 * ip->ihl;
	} else if (ip->version == 6) { // It is in the same place for IPv4 and IPv6, so it's acceptable abuse
		const struct ip6_hdr *ip6 = (const struct ip6_hdr *)header->iphdr;
		if (data_len < sizeof *ip6)
			return '\0'; // Not complete IPv6 address
		if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != 6)
			return '\0'; // Not TCP
		*addr_len = 16;
		*addr = ip6->ip6_dst.s6_addr;
		ip_len = sizeof *ip6;
	} else {
		return '\0';
	}
	if (data_len < sizeof *header + ip_len + 8)
		return '\0'; // We were promised to have 8 bytes of the TCP header, but they are not here
	const struct ports *ports = (const struct ports *)(header->iphdr + ip_len);
	*loc_port = ntohs(ports->source);
	*dest_port = ntohs(ports->destination);
	if (packet->app_protocol == 'i')
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
			case 4: // Fragmentation is OK, the source will retry. This is a soft-NAK.
				return '\0';
			default:
				return 'O';
		}
	else
		switch (header->code) {
			case 0:
				return 'N';
			case 1:
				return 'A';
			case 3:
				return 'H';
			case 4:
				return 'P';
			default:
				return 'O';
		}
}

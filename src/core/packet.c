#include "packet.h"

// These are for the IP header structs.
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <stdbool.h>
#include <string.h>

static void parse_internal(struct packet_info *packet) {
	/*
	 * Try to put the packet into the form for an IP packet. We're lucky, the version field
	 * is on the same place for v6 as for v4, so it works.
	 */
	const struct iphdr *iphdr = packet->data;
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
			break;
		case 6: {
			// It's an IPv6 packet, put it into a v6 form instead.
			const struct ip6_hdr *ip6 = packet->data;
			if (packet->length < sizeof *ip6) {
				// It claims to be an IPv6 packet, but it's too short for that.
				packet->ip_protocol = 0;
				return;
			}
			packet->addresses[END_SRC] = &ip6->ip6_src;
			packet->addresses[END_DST] = &ip6->ip6_dst;
			break;
		}
		default: // Something else. Don't try to find TCP/UDP.
			return;
	}
	packet->direction = DIR_UNKNOWN;
	packet->app_protocol = '?';
}

// Zero or reset the some fields according to other fields, if they don't make sense in that context.
static void postprocess(struct packet_info *packet) {
	bool ip_known = (packet->ip_protocol == 4 || packet->ip_protocol == 6);
	if (!ip_known) {
		memset(&packet->addresses, 0, sizeof packet->addresses);
		packet->addr_len = 0;
		packet->app_protocol = '\0';
		// We don't even know the direction if we don't have the addresses
		packet->direction = DIR_UNKNOWN;
	}
	bool proto_known = (packet->app_protocol == 'T' || packet->app_protocol == 'U');
	if (!proto_known) {
		memset(&packet->ports, 0, sizeof packet->ports);
		packet->hdr_length = 0;
	}
}

void parse_packet(struct packet_info *packet) {
	parse_internal(packet);
	postprocess(packet);
}

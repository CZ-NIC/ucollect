#include "packet.h"
#include "mem_pool.h"
#include "address.h"

// These are for the IP header structs.
#include <netinet/ip.h>
#include <netinet/ip6.h>

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

static void parse_internal(struct packet_info *packet, const struct address_list *local_addresses, struct mem_pool *pool) {
	packet->app_protocol_raw = 0xff;
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

	// Do direction guessing
	bool internal[END_COUNT];
	for (size_t i = 0; i < END_COUNT; i ++)
		internal[i] = addr_in_net_list(packet->addresses[i], packet->addr_len, local_addresses);
	if (internal[END_SRC] && !internal[END_DST])
		packet->direction = DIR_OUT;
	else if (!internal[END_SRC] && internal[END_DST])
		packet->direction = DIR_IN;
	else
		packet->direction = DIR_UNKNOWN;
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
			packet->app_protocol = packet->app_protocol_raw == 4 ? '4' : 6;
			// Create a new structure for the packet and parse recursively
			struct packet_info *next = mem_pool_alloc(pool, sizeof *packet->next);
			packet->next = next;
			next->data = below_ip;
			next->length = length_rest;
			next->interface = packet->interface;
			parse_packet(next, local_addresses, pool);
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
	bool ip_known = (packet->ip_protocol == 4 || packet->ip_protocol == 6);
	if (!ip_known) {
		memset(&packet->addresses, 0, sizeof packet->addresses);
		packet->addr_len = 0;
		packet->app_protocol = '\0';
		// We don't even know the direction if we don't have the addresses
		packet->direction = DIR_UNKNOWN;
	}
	bool has_ports = (packet->app_protocol == 'T' || packet->app_protocol == 'U');
	if (!has_ports) {
		memset(&packet->ports, 0, sizeof packet->ports);
		packet->hdr_length = 0;
	}
	bool is_encapsulation = (packet->app_protocol == '4' || packet->app_protocol == '6');
	if (!is_encapsulation) {
		packet->next = NULL;
	}
	if (packet->app_protocol != 'T')
		packet->tcp_flags = 0;
}

void parse_packet(struct packet_info *packet, const struct address_list *local_addresses, struct mem_pool *pool) {
	parse_internal(packet, local_addresses, pool);
	postprocess(packet);
}

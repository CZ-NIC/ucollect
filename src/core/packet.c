#include "packet.h"

// These are for the IP header structs.
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <stdbool.h>
#include <string.h>

static void parse_internal(struct packet_info *packet) {
	packet->ip_protocol = 0;
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

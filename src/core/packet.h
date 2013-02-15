#ifndef UCOLLECT_PACKET_H
#define UCOLLECT_PACKET_H

#include <stddef.h>
#include <stdint.h>

// One endpoint of communication.
enum endpoint {
	END_SRC,  // The source endpoint
	END_DST,  // The destination endpoint
	END_COUNT // Not a real endpoint, but a stop-mark to know the count.
};

// Direction of the packet
enum direction {
	DIR_IN,		// The packet goes in
	DIR_OUT,        // The packet goes out
	DIR_UNKNOWN,    // Can't guess the direction (it might be a packet in internal network)
	DIR_COUNT       // Not a real direction, a stop-mark.
};

struct packet_info {
	// Length and raw data of the packet (starts with IP header or similar on the same level)
	size_t length;
	const unsigned char *data;
	// Textual name of the interface it was captured on
	const char *interface;
	/*
	 * Source and destination address. Raw data (addr_len bytes each).
	 * Is set only with ip_protocol == 4 || 6, otherwise it is undefined.
	 */
	const unsigned char *addresses[END_COUNT];
	/*
	 * Source and destination ports. Converted to the host byte order.
	 * Filled in only in case the app_protocol is T or U.
	 */
	uint16_t ports[END_COUNT];
	// As in iphdr, 6 for IPv6, 4 for IPv4. Others may be present.
	unsigned char ip_protocol;
	/*
	 * The application-facing protocol. Currently, these are recognized:
	 * - T: TCP
	 * - U: UDP
	 * - ?: Other, not recognized protocol.
	 *
	 * This is set only with ip_protocol == 4 || 6, otherwise it is
	 * undefined.
	 */
	char app_protocol;
	// Length of one address field. 0 in case ip_protocol != 4 && 6
	unsigned char addr_len;
	// Direction of the packet.
	enum direction direction;
};

/*
 * Parse the stuff in the passed packet. It expects length and data are already
 * set, it fills the addresses, protocols, etc.
 */
void parse_packet(struct packet_info *packet);

#endif

#ifndef UCOLLECT_PACKET_H
#define UCOLLECT_PACKET_H

#include <stddef.h>

// TODO: Place this publicly, so the plugin can in.
struct packet_info {
	size_t length;
	const unsigned char *data;
	const char *interface;
	// TODO: Define the rest (addresses, protocols, etc).
};

/*
 * Parse the stuff in the passed packet. It expects length and data are already
 * set, it fills the addresses, protocols, etc.
 */
void parse_packet(struct packet_info *packet);

#endif

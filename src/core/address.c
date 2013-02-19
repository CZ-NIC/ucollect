#include "address.h"
#include "mem_pool.h"
#include "util.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

struct address_node {
	struct address address;
	struct address_node *next;
};

struct address_list {
	struct address_node *head, *tail;
	struct mem_pool *pool;
};

#define LIST_NODE struct address_node
#define LIST_BASE struct address_list
#define LIST_NAME(X) address_list_##X
#define LIST_WANT_APPEND_POOL
#include "link_list.h"

struct address_list *address_list_create(struct mem_pool *pool) {
	struct address_list *list = mem_pool_alloc(pool, sizeof *list);
	*list = (struct address_list) {
		.pool = pool
	};
	return list;
}

static const uint8_t partial_bytes[] = {
	0x00, // 00000000
	0x80, // 10000000
	0xc0, // 11000000
	0xe0, // 11100000
	0xf0, // 11110000
	0xf8, // 11111000
	0xfc, // 11111100
	0xfe, // 11111110
	// 11111111 is full byte, not needed
};

static bool parse_mask(const char *txt, struct address *destination) {
	if (!txt) {
		// No mask. Fill with 1, as the whole address must match.
		memset(destination->mask, 0xff, destination->length);
		return true;
	}
	char *err;
	long bits = strtol(txt, &err, 10);
	if (err && *err) {
		/*
		 * It is not a plain number. So it can be an address too.
		 * We use the existing parse_address method to parse it
		 * and copy the result to the mask.
		 */
		struct address mask;
		if (!parse_address(txt, &mask, false))
			return false;
		if (mask.length != destination->length) {
			ulog(LOG_ERROR, "Mismatch between address and mask\n");
			return false;
		}
		memcpy(destination->mask, mask.mask, destination->length);
		return true;
	} else {
		if (bits < 0 || bits > 8 * destination->length) {
			ulog(LOG_ERROR, "Network mask %ld out of range\n", bits);
			return false;
		}
		// Manually set the bits
		size_t fill_pos = bits / 8;
		// Leading full-1 bytes
		memset(destination->mask, 0xff, fill_pos);
		if (bits % 8) { // There's a partially filled byte
			destination->mask[fill_pos] = partial_bytes[bits % 8];
			fill_pos ++;
		}
		// Trailing full-0 bytes
		memset(destination->mask + fill_pos, 0, destination->length - fill_pos);
		return true;
	}
}

bool parse_address(const char *txt, struct address *destination, bool allow_net) {
	size_t length = strlen(txt);
	char txt_cp[length + 1];
	const char *slash;
	const char *mask = NULL;
	if (allow_net && (slash = index(txt, '/'))) { // We allow it to be net and there's a slash
		// We get a copy so we can modify the data
		strcpy(txt_cp, txt); // Safe, we just allocated enough
		size_t offset = slash - txt;
		txt_cp[offset] = '\0'; // Split it at the slash
		txt = txt_cp; // We point to the shortened version now
		mask = txt_cp + 1 + offset; // After the slash there's the mask
	}
	struct addrinfo *addrinfo;
	int result = getaddrinfo(txt, NULL, &(struct addrinfo) { .ai_flags = AI_NUMERICHOST, .ai_socktype = SOCK_DGRAM }, &addrinfo);
	if (result != 0) {
		ulog(LOG_ERROR, "Failed to parse %s as address (%s)\n", txt, gai_strerror(result));
	} else {
		// With numeric IP, there should be exactly 1 address
		assert(addrinfo);
		assert(!addrinfo->ai_next);
		switch (addrinfo->ai_family) {
			case AF_INET:
				destination->length = 4;
				// Copy the IPv4 address
				memcpy(destination->address, &((const struct sockaddr_in *) addrinfo->ai_addr)->sin_addr.s_addr, 4);
				break;
			case AF_INET6:
				destination->length = 16;
				// Copy the IPv6 address
				memcpy(destination->address, ((const struct sockaddr_in6 *) addrinfo->ai_addr)->sin6_addr.s6_addr, 16);
				break;
			default:
				ulog(LOG_ERROR, "Got unknown address family for %s - is it IP address?\n", txt);
				result = -1; // Don't return yet, go through the freeaddrinfo below and return false then
				break;
		}
	}
	freeaddrinfo(addrinfo);
	if (result == 0)
		if(!parse_mask(mask, destination)) // Fill in the network mask too
			return false;
	return result == 0;
}

void address_list_add(struct address_list *list, const struct address *address) {
	address_list_append_pool(list, list->pool)->address = *address;
}

bool address_list_add_parsed(struct address_list *list, const char *address, bool allow_net) {
	struct address address_bin;
	if (!parse_address(address, &address_bin, allow_net))
		return false;
	address_list_add(list, &address_bin);
	return true;
}

bool addr_in_net(const struct address *address, const struct address *net) {
	if (address->length != net->length)
		/*
		 * Different address family, they can't match
		 * Note we don't consider IPv4-in-IPv6 address space mapped
		 * addresses, as these are mostly an API hack. They should not
		 * be seen on the wild net.
		 */
		return false;
	assert(address->length <= MAX_ADDR_LEN);
	uint8_t masked[MAX_ADDR_LEN];
	// Relying on the compiler to group the bytes to chunks of size comfortable for CPU
	for (size_t i = 0; i < address->length; i ++)
		masked[i] = address->address[i] & net->mask[i];
	return memcmp(masked, net->address, address->length) == 0;
}

bool addr_in_net_list(const struct address *address, const struct address_list *list) {
	for (const struct address_node *net = list->head; net; net = net->next)
		if (addr_in_net(address, &net->address))
			return true;
	return false;
}

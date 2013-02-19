#ifndef UCOLLECT_ADDRESS_H
#define UCOLLECT_ADDRESS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct mem_pool;
struct address_list;

// The IPv6 has 16 bytes (we don't support larger addresses yet)
#define MAX_ADDR_LEN 16

struct address {
	// The address itself
	uint8_t address[MAX_ADDR_LEN];
	// The network mask (if any, depends on context)
	uint8_t mask[MAX_ADDR_LEN];
	// Length of the address in bytes (depends on the version, currently 4 of 16)
	uint8_t length;
};

/*
 * Parse address (IPv4 or IPv6) to the binary representation.
 *
 * If allow_net is true, it allows for the address/mask notation too, where
 * mask can be either other address or a number, specifying how many bits from
 * the beginning to turn to 1.
 */
bool parse_address(const char *txt, struct address *destination, bool allow_net);

// Create an empty list. The pool will be used for content allocation too.
struct address_list *address_list_create(struct mem_pool *pool) __attribute__((nonnull)) __attribute__((malloc));
// Add an address to the list. Takes a copy.
void address_list_add(struct address_list *list, const struct address *address) __attribute__((nonnull));
// Add another address to a list, parsed from a textual representation. Wrapper from above functions.
bool address_list_add_parsed(struct address_list *list, const char *address, bool allow_net) __attribute__((nonnull));

// Is address inside net (address with mask)
bool addr_in_net(const uint8_t *address, size_t addr_len, const struct address *net) __attribute__((nonnull)) __attribute__((const));
// Or in one of many nets?
bool addr_in_net_list(const uint8_t *address, size_t addr_len, const struct address_list *list) __attribute__((nonnull)) __attribute__((const));

#endif

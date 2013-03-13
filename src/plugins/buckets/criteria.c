#include "criteria.h"

#include "../../core/packet.h"
#include "../../core/mem_pool.h"

#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

// IPv6 is 16 bytes long, preceded by the version byte. We pad v4 by zeroes.
#define ADDR_SIZE 17
#define PORT_SIZE sizeof(uint16_t)

static bool copy_ip(uint8_t *where, const struct packet_info *packet) {
	enum endpoint remote = remote_endpoint(packet->direction);
	if (remote == END_COUNT)
		return false; // Strange packet, not going in or out.
	if (!packet->addresses[remote])
		return false; // Not an IP packet.
	size_t len = packet->addr_len;
	assert(ADDR_SIZE - 1 >= len);
	memcpy(where + 1, packet->addresses[remote], len);
	memset(where + 1 + len, 0, ADDR_SIZE - 1 - len);
	*where = packet->ip_protocol;
	return true;
}

static const uint8_t *extract_ip_address(const struct packet_info *packet, struct mem_pool *tmp_pool) {
	uint8_t *result = mem_pool_alloc(tmp_pool, ADDR_SIZE);
	if (!copy_ip(result, packet))
		return NULL;
	return result;
}

static bool copy_port(uint8_t *where, const struct packet_info *packet) {
	enum endpoint remote = remote_endpoint(packet->direction);
	if (remote == END_COUNT)
		return false;
	if (packet->ports[remote] == 0)
		return false;
	uint16_t port_net = htons(packet->ports[remote]);
	memcpy(where, &port_net, sizeof port_net);
	return true;
}

static const uint8_t *extract_port(const struct packet_info *packet, struct mem_pool *tmp_pool) {
	uint8_t *result = mem_pool_alloc(tmp_pool, PORT_SIZE);
	if (copy_port(result, packet))
		return result;
	else
		return NULL;
}

static const uint8_t *extract_both(const struct packet_info *packet, struct mem_pool *tmp_pool) {
	uint8_t *result = mem_pool_alloc(tmp_pool, PORT_SIZE + ADDR_SIZE);
	if (copy_port(result, packet) && copy_ip(result + PORT_SIZE, packet))
		return result;
	else
		return NULL;
}

struct criterion_def criteria[] = {
	{ // Remote address
		.key_size = ADDR_SIZE,
		.name = 'I',
		.extract_key = extract_ip_address
	},
	{ // Remote port
		.key_size = PORT_SIZE,
		.name = 'P',
		.extract_key = extract_port
	},
	{ // Both port and address
		.key_size = PORT_SIZE + ADDR_SIZE,
		.name = 'B',
		.extract_key = extract_both
	},
	{ // Sentinel
		.name = '\0'
	}
};

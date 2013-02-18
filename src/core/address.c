#include "address.h"
#include "mem_pool.h"

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

bool parse_address(const char *txt, struct address *destination, bool allow_net) {
	// TODO: Implement parsing
	return false;
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

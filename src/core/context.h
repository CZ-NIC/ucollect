#ifndef UCOLLECT_CONTEXT_H
#define UCOLLECT_CONTEXT_H

// Forward declarations
struct mem_pool;
struct loop;
/*
 * This is not a true forward declaration. This is not defined in this library at all.
 * We expect each plugin defines its own version. This is slightly better than
 * plain type casting, as the compiler does some minimal checks about type safety
 * inside the same plugin.
 */
struct user_data;

struct context {
	struct mem_pool *permanent_pool;
	struct mem_pool *temp_pool;
	struct loop *loop;
	struct uplink *uplink;
	struct user_data *user_data;
};

#endif

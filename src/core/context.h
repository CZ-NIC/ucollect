#ifndef UCOLLECT_CONTEXT_H
#define UCOLLECT_CONTEXT_H

struct mem_pool;

struct context {
	struct mem_pool *permanent_pool;
	struct mem_pool *temp_pool;
	void *user_data;
};

/*
 * Currently active context. For things like signal handlers and debug,
 * not to be used directly. A copy should be always passed to the callback.
 */
extern struct context *current_context;

#endif

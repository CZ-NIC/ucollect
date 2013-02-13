#include "loop.h"
#include "mem_pool.h"

#include <stdbool.h>

struct loop {
	struct mem_pool *permanent_pool;
	bool stopped;
};

struct loop *loop_create() {
	struct mem_pool *pool = mem_pool_create("Global permanent pool");
	struct loop *result = mem_pool_alloc(pool, sizeof *result);
	*result = (struct loop) {
		.permanent_pool = pool,
		.stopped = false
	};
	return result;
}

void loop_stop(struct loop *loop) {
	loop->stopped = true;
}

void loop_run(struct loop *loop) {
	while (!loop->stopped) {
		// TODO
	}
}

void loop_destroy(struct loop *loop) {
	// This mempool must be destroyed last, as the loop is allocated from it
	mem_pool_destroy(loop->permanent_pool);
}

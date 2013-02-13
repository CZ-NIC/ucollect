#include "loop.h"
#include "mem_pool.h"

#include <signal.h> // for sig_atomic_t

struct loop {
	struct mem_pool *permanent_pool;
	sig_atomic_t stopped; // We may be stopped from a signal, so not bool
};

struct loop *loop_create() {
	struct mem_pool *pool = mem_pool_create("Global permanent pool");
	struct loop *result = mem_pool_alloc(pool, sizeof *result);
	*result = (struct loop) {
		.permanent_pool = pool,
		.stopped = 0
	};
	return result;
}

void loop_break(struct loop *loop) {
	loop->stopped = 1;
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

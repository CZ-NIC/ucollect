#include "uplink.h"
#include "mem_pool.h"
#include "loop.h"
#include "util.h"

struct uplink {
	struct loop *loop;
	struct mem_pool *buffer_pool;
	const char *remote_name, *service;
	int fd;
};

// Connect to remote. Blocking. May abort (that one should be solved by retries in future)
static void connect(struct uplink *uplink) {

}

static void disconnect(struct uplink *uplink) {

}

struct uplink *uplink_create(struct loop *loop, const char *remote_name, const char *service) {
	ulog(LOG_INFO, "Creating uplink to %s:%s\n", remote_name, service);
	struct mem_pool *permanent_pool = loop_permanent_pool(loop);
	struct uplink *result = mem_pool_alloc(permanent_pool, sizeof *result);
	*result = (struct uplink) {
		.loop = loop,
		.buffer_pool = loop_pool_create(loop, NULL, mem_pool_printf(loop_temp_pool(loop), "Buffer pool for uplink to %s:%s", remote_name, service)),
		.remote_name = mem_pool_strdup(permanent_pool, remote_name),
		.service = mem_pool_strdup(permanent_pool, service),
		.fd = -1
	};
	connect(result);
	return result;
}

void uplink_destroy(struct uplink *uplink) {
	ulog(LOG_INFO, "Destroying uplink to %s:%s\n", uplink->remote_name, uplink->service);
	// The memory pools get destroyed by the loop, we just close the socket, if any.
	disconnect(uplink);
}

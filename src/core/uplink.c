#include "uplink.h"
#include "mem_pool.h"
#include "loop.h"
#include "util.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

struct uplink {
	// Will always be uplink_read, this is to be able to use it as epoll_handler
	void (*uplink_read)(struct uplink *uplink, uint32_t events);
	struct loop *loop;
	struct mem_pool *buffer_pool;
	const char *remote_name, *service;
	int fd;
};

static bool uplink_connect_internal(struct uplink *uplink, const struct addrinfo *addrinfo) {
	if (!addrinfo) // No more addresses to try
		return false;
	// Try getting a socket.
	int sock = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
	if (sock == -1) {
		ulog(LOG_WARN, "Couldn't create socket of family %d, type %d and protocol %d (%s)\n", addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol, strerror(errno));
		// Try other
		return uplink_connect_internal(uplink, addrinfo->ai_next);
	}
	// If that works, try connecting it
	int error = connect(sock, addrinfo->ai_addr, addrinfo->ai_addrlen);
	if (error != 0) {
		ulog(LOG_WARN, "Couldn't connect socket %d (%s)\n", sock, strerror(errno));
		error = close(sock);
		if (error != 0)
			ulog(LOG_ERROR, "Couldn't close socket %d (%s), leaking FD\n", sock, strerror(errno));
		return uplink_connect_internal(uplink, addrinfo->ai_next);
	}
	// Hurray, everything worked. Now we are done.
	ulog(LOG_DEBUG, "Connected to uplink %s:%s by fd %d\n", uplink->remote_name, uplink->service, sock);
	uplink->fd = sock;
	return true;
}

// Connect to remote. Blocking. May abort (that one should be solved by retries in future)
static void uplink_connect(struct uplink *uplink) {
	assert(uplink->fd == -1);
	struct addrinfo *remote;
	int result = getaddrinfo(uplink->remote_name, uplink->service, &(struct addrinfo) { .ai_socktype = SOCK_STREAM }, &remote);
	if (result != 0)
		die("Failed to resolve the uplink %s:%s (%s)\n", uplink->remote_name, uplink->service, gai_strerror(result));
	bool connected = uplink_connect_internal(uplink, remote);
	freeaddrinfo(remote);
	if (!connected)
		// TODO: Some retry after a while instead of hard die
		die("Failed to connect to any address and port for uplink %s:%s\n", uplink->remote_name, uplink->service);
	loop_register_fd(uplink->loop, uplink->fd, (struct epoll_handler *) uplink);
	// TODO: Send hello
}

static void uplink_disconnect(struct uplink *uplink) {
	if (uplink->fd != -1) {
		ulog(LOG_DEBUG, "Closing uplink connection %d to %s:%s\n", uplink->fd, uplink->remote_name, uplink->service);
		int result = close(uplink->fd);
		if (result != 0)
			ulog(LOG_ERROR, "Couldn't close uplink connection to %s:%s, leaking file descriptor %d (%s)\n", uplink->remote_name, uplink->service, uplink->fd, strerror(errno));
		uplink->fd = -1;
	} else
		ulog(LOG_DEBUG, "Uplink connection to %s:%s not open\n", uplink->remote_name, uplink->service);
}

static void uplink_read(struct uplink *uplink, uint32_t unused) {
	(void) unused;
	ulog(LOG_DEBUG, "Read on uplink %s:%s (%d)\n", uplink->remote_name, uplink->service, uplink->fd);
}

struct uplink *uplink_create(struct loop *loop, const char *remote_name, const char *service) {
	ulog(LOG_INFO, "Creating uplink to %s:%s\n", remote_name, service);
	struct mem_pool *permanent_pool = loop_permanent_pool(loop);
	struct uplink *result = mem_pool_alloc(permanent_pool, sizeof *result);
	*result = (struct uplink) {
		.uplink_read = uplink_read,
		.loop = loop,
		.buffer_pool = loop_pool_create(loop, NULL, mem_pool_printf(loop_temp_pool(loop), "Buffer pool for uplink to %s:%s", remote_name, service)),
		.remote_name = mem_pool_strdup(permanent_pool, remote_name),
		.service = mem_pool_strdup(permanent_pool, service),
		.fd = -1
	};
	uplink_connect(result);
	return result;
}

void uplink_destroy(struct uplink *uplink) {
	ulog(LOG_INFO, "Destroying uplink to %s:%s\n", uplink->remote_name, uplink->service);
	// The memory pools get destroyed by the loop, we just close the socket, if any.
	uplink_disconnect(uplink);
}

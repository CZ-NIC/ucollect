#include "uplink.h"
#include "mem_pool.h"
#include "loop.h"
#include "util.h"
#include "context.h"
#include "tunable.h"

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
	const uint8_t *buffer;
	uint8_t *buffer_pos;
	size_t buffer_size, size_rest;
	uint32_t reconnect_timeout;
	bool has_size;
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

static void connect_fail(struct uplink *uplink);

// Connect to remote. Blocking. May abort (that one should be solved by retries in future)
static void uplink_connect(struct uplink *uplink) {
	assert(uplink->fd == -1);
	struct addrinfo *remote;
	int result = getaddrinfo(uplink->remote_name, uplink->service, &(struct addrinfo) { .ai_socktype = SOCK_STREAM }, &remote);
	if (result != 0) {
		ulog(LOG_ERROR, "Failed to resolve the uplink %s:%s (%s)\n", uplink->remote_name, uplink->service, gai_strerror(result));
		connect_fail(uplink);
		return;
	}
	bool connected = uplink_connect_internal(uplink, remote);
	freeaddrinfo(remote);
	if (!connected) {
		ulog(LOG_ERROR, "Failed to connect to any address and port for uplink %s:%s\n", uplink->remote_name, uplink->service);
		connect_fail(uplink);
		return;
	}
	// We connected. Reset the reconnect timeout.
	uplink->reconnect_timeout = 0;
	loop_register_fd(uplink->loop, uplink->fd, (struct epoll_handler *) uplink);
	/*
	 * Send 'H'ello. For now, it is empty. In future, we expect to have program & protocol version,
	 * list of plugins and possibly other things too.
	 */
	uplink_send_message(uplink, 'H', NULL, 0);
}

static void reconnect_now(struct context *unused, void *data, size_t id_unused) {
	struct uplink *uplink = data;
	(void) unused;
	(void) id_unused;
	ulog(LOG_INFO, "Reconnecting to %s:%s now\n", uplink->remote_name, uplink->service);
	uplink_connect(uplink);
}

static void connect_fail(struct uplink *uplink) {
	if (uplink->reconnect_timeout) {
		// Some subsequent reconnect.
		uplink->reconnect_timeout *= RECONNECT_MULTIPLY;
		if (uplink->reconnect_timeout > RECONNECT_MAX)
			uplink->reconnect_timeout = RECONNECT_MAX;
	} else
		uplink->reconnect_timeout = RECONNECT_BASE;
	ulog(LOG_INFO, "Going to reconnect to %s:%s after %d seconds\n", uplink->remote_name, uplink->service, uplink->reconnect_timeout / 1000);
	loop_timeout_add(uplink->loop, uplink->reconnect_timeout, NULL, uplink, reconnect_now);
}

static void buffer_reset(struct uplink *uplink) {
	uplink->buffer_size = uplink->size_rest = 0;
	uplink->buffer = uplink->buffer_pos = NULL;
	uplink->has_size = false;
	mem_pool_reset(uplink->buffer_pool);
}

static void uplink_disconnect(struct uplink *uplink) {
	if (uplink->fd != -1) {
		ulog(LOG_DEBUG, "Closing uplink connection %d to %s:%s\n", uplink->fd, uplink->remote_name, uplink->service);
		int result = close(uplink->fd);
		if (result != 0)
			ulog(LOG_ERROR, "Couldn't close uplink connection to %s:%s, leaking file descriptor %d (%s)\n", uplink->remote_name, uplink->service, uplink->fd, strerror(errno));
		uplink->fd = -1;
		buffer_reset(uplink);
	} else
		ulog(LOG_DEBUG, "Uplink connection to %s:%s not open\n", uplink->remote_name, uplink->service);
}

const char *uplink_parse_string(struct mem_pool *pool, const uint8_t **buffer, size_t *length) {
	size_t len_size = sizeof(uint32_t);
	if (*length < len_size) {
		return NULL;
	}
	const uint32_t len = ntohl(*(const uint32_t *) *buffer);
	if (*length < len + len_size) {
		return NULL;
	}
	char *result = mem_pool_alloc(pool, len + 1);
	memcpy(result, *buffer + len_size, len);
	result[len] = '\0';
	*length -= len_size + len;
	*buffer += len_size + len;
	return result;
}

static void handle_buffer(struct uplink *uplink) {
	if (uplink->has_size) {
		// If we already have the size, it is the real message
		ulog(LOG_DEBUG, "Uplink %s:%s received complete message of %zu bytes\n", uplink->remote_name, uplink->service, uplink->buffer_size);

		if (uplink->buffer_size) {
			char command = *uplink->buffer ++;
			uplink->buffer_size --;
			switch (command) {
				case 'R': { // Route data to given plugin
					const char *plugin_name = uplink_parse_string(uplink->buffer_pool, &uplink->buffer, &uplink->buffer_size);
					if (!loop_plugin_send_data(uplink->loop, plugin_name, uplink->buffer, uplink->buffer_size)) {
						ulog(LOG_ERROR, "Plugin %s referenced by uplink does not exist\n", plugin_name);
						// TODO: Create some function for formatting messages
						size_t pname_len = strlen(plugin_name);
						// 1 for 'P', 1 for '\0' at the end
						size_t msgsize = 1 + sizeof pname_len + pname_len;
						char buffer[msgsize];
						// First goes error specifier - 'P'lugin name doesn't exist
						buffer[0] = 'P';
						// Then one byte after, the length of the name
						*(uint32_t *)(buffer + 1) = htonl(pname_len);
						// And the string itself
						memcpy(buffer + 1 + sizeof pname_len, plugin_name, pname_len);
						// Send an error
						uplink_send_message(uplink, 'E', buffer, msgsize);
					}
					break;
				}
				default:
					ulog(LOG_ERROR, "Received unknown command %c from uplink %s:%s\n", command, uplink->remote_name, uplink->service);
					break;
			}
		} else {
			ulog(LOG_ERROR, "Received an empty message from %s:%s\n", uplink->remote_name, uplink->service);
		}

		// Next time start a new message from scratch
		buffer_reset(uplink);
	} else {
		// This is the size of the real message. Get the buffer for the message.
		uplink->buffer_size = uplink->size_rest = ntohl(*(const uint32_t *) uplink->buffer);
		uplink->buffer = uplink->buffer_pos = mem_pool_alloc(uplink->buffer_pool, uplink->buffer_size);
		uplink->has_size = true;
	}
}

static void uplink_read(struct uplink *uplink, uint32_t unused) {
	(void) unused;
	ulog(LOG_DEBUG, "Read on uplink %s:%s (%d)\n", uplink->remote_name, uplink->service, uplink->fd);
	if (!uplink->buffer) {
		// No buffer - prepare one for the size
		uplink->buffer_size = uplink->size_rest = sizeof(uint32_t);
		uplink->buffer = uplink->buffer_pos = mem_pool_alloc(uplink->buffer_pool, uplink->buffer_size);
	}
	// Read once. If there's more to read, the loop will call us again. We just don't want to process for too long.
	ssize_t amount = recv(uplink->fd, uplink->buffer_pos, uplink->size_rest, MSG_DONTWAIT);
	if (amount == -1) {
		switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
			case EINTR:
				/*
				 * Non-fatal errors. EINTR can happen without problems.
				 *
				 * EAGAIN/EWOULDBLOCK should not, but it is said linux can create spurious
				 * events on sockets sometime.
				 */
				ulog(LOG_WARN, "Non-fatal error reading from %s:%s (%d): %s\n", uplink->remote_name, uplink->service, uplink->fd, strerror(errno));
				return; // We'll just retry next time
			case ECONNRESET:
				// This is similar to close
				ulog(LOG_WARN, "Connection to %s:%s reset, reconnecting\n", uplink->remote_name, uplink->service);
				goto CLOSED;
			default: // Other errors are fatal, as we don't know the cause
				die("Error reading from uplink %s:%s (%s)\n", uplink->remote_name, uplink->service, strerror(errno));
		}
	} else if (amount == 0) { // 0 means socket closed
		ulog(LOG_WARN, "Remote closed the uplink %s:%s, reconnecting\n", uplink->remote_name, uplink->service);
		CLOSED:
		uplink_disconnect(uplink);
		uplink_connect(uplink);
	} else {
		uplink->buffer_pos += amount;
		uplink->size_rest -= amount;
		if (uplink->size_rest == 0)
			handle_buffer(uplink);
	}
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
	loop_uplink_set(loop, result);
	return result;
}

void uplink_destroy(struct uplink *uplink) {
	ulog(LOG_INFO, "Destroying uplink to %s:%s\n", uplink->remote_name, uplink->service);
	// The memory pools get destroyed by the loop, we just close the socket, if any.
	uplink_disconnect(uplink);
}

static bool buffer_send(struct uplink *uplink, const uint8_t *buffer, size_t size) {
	while (size > 0) {
		// TODO: Do we want to play with the MSG_MORE?
		ssize_t amount = send(uplink->fd, buffer, size, MSG_NOSIGNAL);
		if (amount == -1) {
			switch (errno) {
				case EINTR:
					// Just interrupt called during send. Retry.
					ulog(LOG_WARN, "EINTR during send to %s:%s\n", uplink->remote_name, uplink->service);
					continue;
				case ECONNRESET:
				case EPIPE:
					// Lost connection. Reconnect.
					uplink_disconnect(uplink);
					uplink_connect(uplink);
					return false;
				default:
					// Fatal errors
					die("Error sending to %s:%s\n", uplink->remote_name, uplink->service);
			}
		} else {
			buffer += amount;
			size -= amount;
		}
	}
	return true;
}

bool uplink_send_message(struct uplink *uplink, char type, const void *data, size_t size) {
	// The +1 is for the type sent directly after the length
	size_t head_len = sizeof(uint32_t) + 1;
	uint8_t head_buffer[head_len];
	*(uint32_t *) head_buffer = htonl(size + 1);
	head_buffer[head_len - 1] = type;
	return buffer_send(uplink, head_buffer, head_len) && buffer_send(uplink, data, size);
}

bool uplink_plugin_send_message(struct context *context, const void *data, size_t size) {
	const char *name = loop_plugin_get_name(context);
	ulog(LOG_DEBUG, "Sending message of size %zu from plugin %s\n", size, name);
	uint32_t name_length = strlen(name);
	uint32_t length = sizeof name_length + name_length + size;
	uint8_t buffer[length];
	*(uint32_t *)buffer = htonl(name_length);
	memcpy(buffer + sizeof name_length, name, name_length);
	memcpy(buffer + sizeof name_length + name_length, data, size);
	return uplink_send_message(context->uplink, 'R', buffer, length);
}

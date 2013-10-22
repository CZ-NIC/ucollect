/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "uplink.h"
#include "mem_pool.h"
#include "loop.h"
#include "util.h"
#include "context.h"
#include "tunable.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <atsha204.h>

#ifdef SOFT_LOGIN
static const uint8_t *compute_response_soft(const uint8_t *challenge, size_t clen, const char *password, struct mem_pool *pool) {
	uint8_t *output = mem_pool_alloc(pool, SHA256_DIGEST_LENGTH);
	SHA256_CTX context;
	SHA256_Init(&context);
	SHA256_Update(&context, password, strlen(password));
	SHA256_Update(&context, challenge, clen);
	SHA256_Update(&context, password, strlen(password));
	SHA256_Final(output, &context);
	return output;
}
#else
static void atsha_log_callback(const char *msg) {
	ulog(LLOG_ERROR, "ATSHA: %s\n", msg);
}
#endif

static void gen_random(uint8_t *buffer, size_t size) {
	// Generate a challenge. Just load some data from /dev/urandom.
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		die("Couldn't open urandom (%s)\n", strerror(errno));
	// Read by 1 character, as urandom is strange and might give only little data
	for (size_t i = 0; i < size; i ++)
		if (read(fd, buffer + i, 1) != 1)
			die("Couldn't read from urandom (%s)\n", strerror(errno));
	close(fd);
}

enum auth_status {
	AUTHENTICATED,
	SENT,
	NOT_STARTED
};

#define IPV6_LEN 16

struct uplink;

struct err_handler {
	struct epoll_handler handler;
	struct uplink *uplink;
	int fd;
	struct err_handler *next;
};

struct uplink {
	// Will always be uplink_read, this is to be able to use it as epoll_handler
	void (*uplink_read)(struct uplink *uplink, uint32_t events);
	struct loop *loop;
	struct mem_pool *buffer_pool;
	const char *remote_name, *service, *login, *password, *cert;
	const uint8_t *buffer;
	uint8_t *buffer_pos;
	struct err_handler *empty_handler;
	size_t buffer_size, size_rest;
	uint32_t reconnect_timeout;
	bool has_size;
	// Timeouts for pings, etc.
	size_t ping_timeout; // The ID of the timeout.
	size_t pings_unanswered; // Number of pings sent without answer (in a row)
	bool ping_scheduled;
	bool reconnect_scheduled;
	bool seen_data;
	size_t reconnect_id; // The ID of the reconnect timeout
	int fd;
	uint64_t last_connect;
	size_t addr_len;
	uint8_t address[IPV6_LEN];
	uint8_t server_login[CHALLENGE_LEN];
	enum auth_status auth_status;
};

static void uplink_disconnect(struct uplink *uplink, bool reset_reconnect);
static void connect_fail(struct uplink *uplink);

static void err_read(void *data, uint32_t unused) {
	(void) unused;
	struct err_handler *handler = data;
	if (handler->fd == -1) {
		ulog(LLOG_DEBUG, "Received stray read on socat error socket\n");
		uplink_disconnect(handler->uplink, true);
		connect_fail(handler->uplink);
		return;
	}
#define bufsize 1024
	char buffer[bufsize + 1];
	ssize_t result = recv(handler->fd, buffer, bufsize, MSG_DONTWAIT);
	switch (result) {
		case -1:
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return; // This is OK
			} else {
				ulog(LLOG_ERROR, "Error reading errors from socat: %s\n", strerror(errno));
				// Fall through to close
			}
		case 0:
			close(handler->fd);
			handler->fd = -1;
			handler->next = handler->uplink->empty_handler;
			handler->uplink->empty_handler = handler;
			break;
		default: {
			char *pos = buffer;
			buffer[result] = '\0';
			// Split to lines, skip empty ones and print the stuff
			while (pos && *pos) {
				char *end = index(pos, '\n');
				if (end)
					*end = '\0';
				if (*(pos + 1))
					ulog(LLOG_ERROR, "Error from socat: %s\n", pos);
				pos = end;
				if (pos)
					pos ++;
			}
			break;
		}
	}
}

static bool uplink_connect_internal(struct uplink *uplink) {
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
		ulog(LLOG_ERROR, "Couldn't create socket pair: %s\n", strerror(errno));
		return false;
	}
	int errs[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, errs) == -1) {
		close(sockets[0]);
		close(sockets[1]);
		ulog(LLOG_ERROR, "Couldn't create error sockets: %s\n", strerror(errno));
		return false;
	}
	pid_t socat = fork();
	if (socat == -1) {
		close(sockets[0]);
		close(sockets[1]);
		close(errs[0]);
		close(errs[1]);
		ulog(LLOG_ERROR, "Can't fork: %s\n", strerror(errno));
		return false;
	}
	if (socat) {
		close(sockets[1]);
		close(errs[1]);
		uplink->fd = sockets[0];
		uplink->auth_status = NOT_STARTED;
		struct err_handler *handler = uplink->empty_handler;
		if (handler) {
			uplink->empty_handler = handler->next;
		} else {
			handler = mem_pool_alloc(loop_permanent_pool(uplink->loop), sizeof *handler);
		}
		*handler = (struct err_handler) {
			.handler = {
				.handler = err_read
			},
			.fd = errs[0],
			.uplink = uplink
		};
		loop_register_fd(uplink->loop, errs[0], &handler->handler);
		ulog(LLOG_INFO, "Socat started\n");
		return true;
	} else {
		close(sockets[0]);
		close(errs[0]);
		if (dup2(sockets[1], 0) == -1 || dup2(sockets[1], 1) == -1 || dup2(errs[1], 2) == -1) {
			ulog(LLOG_ERROR, "Couldn't dup: %s\n", strerror(errno));
			exit(1);
		}
		close(sockets[1]);
		close(errs[1]);
		const char *remote = mem_pool_printf(loop_temp_pool(uplink->loop), "OPENSSL:%s:%s,cafile=%s,compress=auto,cipher=TLSv1:!MEDIUM:!LOW:!aNULL,", uplink->remote_name, uplink->service, uplink->cert);
		execlp("socat", "socat", "STDIO", remote, (char *) NULL);
		die("Exec should never exit but it did: %s\n", strerror(errno));
	}
}

static void send_ping(struct context *context, void *data, size_t id);

// Connect to remote. Blocking.
static void uplink_connect(struct uplink *uplink) {
	assert(uplink->fd == -1);
	if (uplink->last_connect + RECONN_TIME > loop_now(uplink->loop)) {
		ulog(LLOG_WARN, "Reconnecting too often, waiting a little while\n");
		connect_fail(uplink);
		return;
	}
	uplink->last_connect = loop_now(uplink->loop);
	bool connected = uplink_connect_internal(uplink);
	if (!connected) {
		ulog(LLOG_ERROR, "Failed to connect to any address and port for uplink %s:%s\n", uplink->remote_name, uplink->service);
		connect_fail(uplink);
		return;
	}
	// We connected. Reset the reconnect timeout.
	if (uplink->seen_data)
		uplink->reconnect_timeout = 0;
	uplink->seen_data = false;
	// Reset the pings.
	uplink->pings_unanswered = 0;
	uplink->ping_timeout = loop_timeout_add(uplink->loop, PING_TIMEOUT, NULL, uplink, send_ping);
	uplink->ping_scheduled = true;
	loop_register_fd(uplink->loop, uplink->fd, (struct epoll_handler *) uplink);
}

static void reconnect_now(struct context *unused, void *data, size_t id_unused) {
	struct uplink *uplink = data;
	(void) unused;
	(void) id_unused;
	ulog(LLOG_INFO, "Reconnecting to %s:%s now\n", uplink->remote_name, uplink->service);
	uplink->reconnect_scheduled = false;
	uplink_connect(uplink);
}

static void connect_fail(struct uplink *uplink) {
	assert(!uplink->reconnect_scheduled);
	if (uplink->reconnect_timeout) {
		// Some subsequent reconnect.
		uplink->reconnect_timeout *= RECONNECT_MULTIPLY;
		if (uplink->reconnect_timeout > RECONNECT_MAX)
			uplink->reconnect_timeout = RECONNECT_MAX;
	} else
		uplink->reconnect_timeout = RECONNECT_BASE;
	ulog(LLOG_INFO, "Going to reconnect to %s:%s after %d seconds\n", uplink->remote_name, uplink->service, uplink->reconnect_timeout / 1000);
	uplink->reconnect_id = loop_timeout_add(uplink->loop, uplink->reconnect_timeout, NULL, uplink, reconnect_now);
	uplink->reconnect_scheduled = true;
}

static void buffer_reset(struct uplink *uplink) {
	uplink->buffer_size = uplink->size_rest = 0;
	uplink->buffer = uplink->buffer_pos = NULL;
	uplink->has_size = false;
	mem_pool_reset(uplink->buffer_pool);
}

static void uplink_disconnect(struct uplink *uplink, bool reset_reconnect) {
	if (uplink->fd != -1) {
		ulog(LLOG_DEBUG, "Closing uplink connection %d to %s:%s\n", uplink->fd, uplink->remote_name, uplink->service);
		loop_uplink_disconnected(uplink->loop);
		int result = close(uplink->fd);
		if (result != 0)
			ulog(LLOG_ERROR, "Couldn't close uplink connection to %s:%s, leaking file descriptor %d (%s)\n", uplink->remote_name, uplink->service, uplink->fd, strerror(errno));
		uplink->fd = -1;
		buffer_reset(uplink);
		if (uplink->ping_scheduled)
			loop_timeout_cancel(uplink->loop, uplink->ping_timeout);
		uplink->ping_scheduled = false;
		if (uplink->reconnect_scheduled && reset_reconnect) {
			loop_timeout_cancel(uplink->loop, uplink->reconnect_id);
			uplink->reconnect_scheduled = false;
		}
		uplink->addr_len = 0;
	} else
		ulog(LLOG_DEBUG, "Uplink connection to %s:%s not open\n", uplink->remote_name, uplink->service);
}

static void send_ping(struct context *context_unused, void *data, size_t id_unused) {
	(void) context_unused;
	(void) id_unused;
	struct uplink *uplink = data;
	uplink->ping_scheduled = false;
	// How long does it not answer pings?
	if (uplink->pings_unanswered >= PING_COUNT) {
		ulog(LLOG_ERROR, "Too many pings not answered on %s:%s, reconnecting\n", uplink->remote_name, uplink->service);
		// Let the connect be called from the loop, so it works even if uplink_disconnect makes a plugin crash
		assert(!uplink->reconnect_scheduled);
		uplink->reconnect_id = loop_timeout_add(uplink->loop, 0, NULL, uplink, reconnect_now);
		uplink->reconnect_scheduled = true;
		uplink->pings_unanswered = 0;
		uplink_disconnect(uplink, false);
		return;
	}
	ulog(LLOG_DEBUG, "Sending ping to %s:%s\n", uplink->remote_name, uplink->service);
	uplink->pings_unanswered ++;
	uplink_send_message(uplink, 'P', NULL, 0);
	// Schedule new ping
	uplink->ping_timeout = loop_timeout_add(uplink->loop, PING_TIMEOUT, NULL, uplink, send_ping);
	uplink->ping_scheduled = true;
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

void uplink_render_string(const void *string, uint32_t length, uint8_t **buffer_pos, size_t *buffer_len) {
	// Network byte order
	uint32_t len_encoded = htonl(length);
	assert(*buffer_len >= length + sizeof(len_encoded));
	// Copy the data
	memcpy(*buffer_pos, &len_encoded, sizeof(len_encoded));
	memcpy(*buffer_pos + sizeof(len_encoded), string, length);
	// Update the buffer position
	*buffer_pos += sizeof(len_encoded) + length;
	*buffer_len -= sizeof(len_encoded) + length;
}

static void handle_buffer(struct uplink *uplink) {
	if (uplink->has_size) {
		// If we already have the size, it is the real message
		ulog(LLOG_DEBUG, "Uplink %s:%s received complete message of %zu bytes\n", uplink->remote_name, uplink->service, uplink->buffer_size);

		if (uplink->buffer_size) {
			char command = *uplink->buffer ++;
			uplink->buffer_size --;
			struct mem_pool *temp_pool = loop_temp_pool(uplink->loop);
			if (uplink->auth_status == AUTHENTICATED) {
				switch (command) {
					case 'R': { // Route data to given plugin
							  const char *plugin_name = uplink_parse_string(uplink->buffer_pool, &uplink->buffer, &uplink->buffer_size);
							  /*
							   * The loop_plugin_send_data contains call to plugin callback.
							   * Such callback can fail and we would like to recover. That is done
							   * by a longjump directly to the loop. That'd mean this function is not
							   * completed, therefore we make sure it works well even in such case -
							   * we create a copy of the buffer and then reset the buffer before
							   * going to the plugin (resetting it again below doesn't hurt anything).
							   */
							  uint8_t *buffer = mem_pool_alloc(temp_pool, uplink->buffer_size);
							  memcpy(buffer, uplink->buffer, uplink->buffer_size);
							  size_t length = uplink->buffer_size;
							  buffer_reset(uplink);
							  if (!loop_plugin_send_data(uplink->loop, plugin_name, buffer, length)) {
								  ulog(LLOG_ERROR, "Plugin %s referenced by uplink does not exist\n", plugin_name);
								  // TODO: Create some function for formatting messages
								  size_t pname_len = strlen(plugin_name);
								  // 1 for 'P', 1 for '\0' at the end
								  size_t msgsize = 1 + sizeof pname_len + pname_len;
								  char buffer[msgsize];
								  // First goes error specifier - 'P'lugin name doesn't exist
								  buffer[0] = 'P';
								  // Then one byte after, the length of the name
								  uint32_t len_n = htonl(pname_len);
								  memcpy(buffer + 1, &len_n, sizeof len_n);
								  // And the string itself
								  memcpy(buffer + 1 + sizeof len_n, plugin_name, pname_len);
								  // Send an error
								  uplink_send_message(uplink, 'E', buffer, msgsize);
							  }
							  break;
						  }
					case 'P': // Ping from the server. Send a pong back.
						  uplink_send_message(uplink, 'p', uplink->buffer, uplink->buffer_size);
						  break;
					case 'p': // Pong. Reset the number of unanswered pings, we got some answer, the link works
						  uplink->pings_unanswered = 0;
						  break;
					default:
						  ulog(LLOG_ERROR, "Received unknown command %c from uplink %s:%s\n", command, uplink->remote_name, uplink->service);
						  break;
				}
			} else {
#ifdef SOFT_LOGIN
				if (command == 'C' && uplink->auth_status == NOT_STARTED) {
					ulog(LLOG_DEBUG, "Sending login info\n");
					// We received the challenge. Compute the response.
					const uint8_t *response = compute_response(uplink->buffer, uplink->buffer_size, uplink->password, temp_pool);
					gen_random(uplink->server_login, CHALLENGE_LEN);
					/*
					 * Compose the message. There are 1 char and 3 strings in there ‒ the version used (currently hardcoded
					 * to 'S' as Software hash), our login name, the response and challenge for the server.
					 */
					size_t len = 1 + 3*sizeof(uint32_t) + strlen(uplink->login) + SHA256_DIGEST_LENGTH + CHALLENGE_LEN;
					uint8_t *message = mem_pool_alloc(temp_pool, len);
					message[0] = 'S';
					uint8_t *message_pos = message + 1;
					size_t len_pos = len - 1;
					uplink_render_string((const uint8_t *) uplink->login, strlen(uplink->login), &message_pos, &len_pos);
					uplink_render_string(response, SHA256_DIGEST_LENGTH, &message_pos, &len_pos);
					uplink_render_string(uplink->server_login, CHALLENGE_LEN, &message_pos, &len_pos);
					assert(!len_pos);
					uplink_send_message(uplink, 'L', message, len);
					uplink->auth_status = SENT;
				} else if (command == 'L' && uplink->auth_status == SENT) {
					ulog(LLOG_DEBUG, "Received server login info\n");
					// We got the server response. Compute our own version and check they are the same.
					const uint8_t *response = compute_response(uplink->server_login, CHALLENGE_LEN, uplink->password, temp_pool);
					if (uplink->buffer_size == CHALLENGE_LEN && memcmp(uplink->buffer, response, CHALLENGE_LEN) == 0) {
						ulog(LLOG_DEBUG, "Server authenticated\n");
						// OK, Login complete. Send hello and tell the rest of the program we're connected.
						/*
						 * Send 'H'ello. For now, it is empty. In future, we expect to have program & protocol version,
						 * list of plugins and possibly other things too.
						 */
						uplink->auth_status = AUTHENTICATED;
						uplink_send_message(uplink, 'H', NULL, 0);
						loop_uplink_connected(uplink->loop);
					} else
						// This is an insult, stop talking to the other side.
						ulog(LLOG_ERROR, "Server failed to authenticated. Password mismatch?\n");
#else
				if (command == 'C' && uplink->auth_status == NOT_STARTED) {
					ulog(LLOG_DEBUG, "Sending login info\n");
					// Get the chip handle
					atsha_set_log_callback(atsha_log_callback);
					struct atsha_handle *cryptochip = atsha_open();
					if (!cryptochip)
						die("Couldn't open the ATSHA204 chip\n");
					// Read the serial number
					atsha_big_int serial;
					int result = atsha_serial_number(cryptochip, &serial);
					if (result != ATSHA_ERR_OK)
						die("Don't known my own name: %s\n", atsha_error_name(result));

#define HALF_SIZE 16
					// Compute response to the server challenge
					atsha_big_int server_challenge, client_response;
					uint8_t local_half[HALF_SIZE] = PASSWD_HALF;
					loop_xor_plugins(uplink->loop, local_half);
					assert(HALF_SIZE + uplink->buffer_size == sizeof(server_challenge.data));
					server_challenge.bytes = HALF_SIZE + uplink->buffer_size;
					memcpy(server_challenge.data, local_half, HALF_SIZE);
					memcpy(server_challenge.data + HALF_SIZE, uplink->buffer, uplink->buffer_size);
					result = atsha_challenge_response(cryptochip, server_challenge, &client_response);
					if (result != ATSHA_ERR_OK)
						die("Can't answer challenge: %s\n", atsha_error_name(result));

					// Generate a challenge for the server and compute expected response
					atsha_big_int client_challenge, server_response;
					client_challenge.bytes = HALF_SIZE + uplink->buffer_size;
					memcpy(client_challenge.data, local_half, HALF_SIZE);
					gen_random(client_challenge.data + HALF_SIZE, uplink->buffer_size);
					result = atsha_challenge_response(cryptochip, client_challenge, &server_response);
					if (result != ATSHA_ERR_OK)
						die("Can't computer expected response: %s\n", atsha_error_name(result));

					atsha_close(cryptochip);

					// Store the expected response
					assert(server_response.bytes == CHALLENGE_LEN);
					memcpy(uplink->server_login, server_response.data, CHALLENGE_LEN);

					// Send all computed stuff
					size_t len = 1 + 3*sizeof(uint32_t) + serial.bytes + client_response.bytes + client_challenge.bytes - HALF_SIZE;
					uint8_t *message = mem_pool_alloc(temp_pool, len);
					message[0] = 'A';
					uint8_t *message_pos = message + 1;
					size_t len_pos = len - 1;
					uplink_render_string(serial.data, serial.bytes, &message_pos, &len_pos);
					uplink_render_string(client_response.data, client_response.bytes, &message_pos, &len_pos);
					uplink_render_string(client_challenge.data + HALF_SIZE, client_challenge.bytes - HALF_SIZE, &message_pos, &len_pos);
					assert(!len_pos);
					uplink_send_message(uplink, 'L', message, len);
					uplink->auth_status = SENT;
				} else if (command == 'L' && uplink->auth_status == SENT) {
					if (uplink->buffer_size == CHALLENGE_LEN && memcmp(uplink->buffer, uplink->server_login, CHALLENGE_LEN) == 0) {
						ulog(LLOG_DEBUG, "Server authenticated\n");
						// OK, Login complete. Send hello and tell the rest of the program we're connected.
						/*
						 * Send 'H'ello. For now, it is empty. In future, we expect to have program & protocol version,
						 * list of plugins and possibly other things too.
						 */
						uplink->auth_status = AUTHENTICATED;
						uplink_send_message(uplink, 'H', NULL, 0);
						loop_uplink_connected(uplink->loop);
					} else
						// This is an insult, stop talking to the other side.
						ulog(LLOG_ERROR, "Server failed to authenticated. Password mismatch?\n");
#endif
				} else if (command == 'F')
					ulog(LLOG_ERROR, "Server rejected our authentication\n");
				else
					// This is an insult, and we won't talk to the other side any more!
					ulog(LLOG_ERROR, "Protocol violation at login\n");
			}
		} else {
			ulog(LLOG_ERROR, "Received an empty message from %s:%s\n", uplink->remote_name, uplink->service);
		}

		// Next time start a new message from scratch
		buffer_reset(uplink);
	} else {
		// This is the size of the real message. Get the buffer for the message.
		uint32_t buffer_size;
		memcpy(&buffer_size, uplink->buffer, sizeof buffer_size);
		uplink->buffer_size = uplink->size_rest = ntohl(buffer_size);
		uplink->buffer = uplink->buffer_pos = mem_pool_alloc(uplink->buffer_pool, uplink->buffer_size);
		uplink->has_size = true;
	}
}

static void uplink_read(struct uplink *uplink, uint32_t unused) {
	(void) unused;
	ulog(LLOG_DEBUG, "Read on uplink %s:%s (%d)\n", uplink->remote_name, uplink->service, uplink->fd);
	if (uplink->fd == -1) {
		ulog(LLOG_WARN, "Spurious read on uplink\n");
		return;
	}
	size_t limit = 50; // Max of 50 messages, so we don't block forever. Arbitrary smallish number.
	while (limit) {
		limit --;
		if (!uplink->buffer) {
			// No buffer - prepare one for the size
			uplink->buffer_size = uplink->size_rest = sizeof(uint32_t);
			uplink->buffer = uplink->buffer_pos = mem_pool_alloc(uplink->buffer_pool, uplink->buffer_size);
		}
		// Read once.
		ssize_t amount = recv(uplink->fd, uplink->buffer_pos, uplink->size_rest, MSG_DONTWAIT);
		if (amount == -1) {
			switch (errno) {
				/*
				 * Non-fatal errors. EINTR can happen without problems.
				 *
				 * EAGAIN/EWOULDBLOCK should not, but it is said linux can create spurious
				 * events on sockets sometime.
				 */
				case EAGAIN:
#if EAGAIN != EWOULDBLOCK
				case EWOULDBLOCK:
#endif
					return;
				case EINTR:
					ulog(LLOG_WARN, "Non-fatal error reading from %s:%s (%d): %s\n", uplink->remote_name, uplink->service, uplink->fd, strerror(errno));
					continue; // We'll just retry next time
				case ECONNRESET:
					// This is similar to close
					ulog(LLOG_WARN, "Connection to %s:%s reset, reconnecting\n", uplink->remote_name, uplink->service);
					goto CLOSED;
				default: // Other errors are fatal, as we don't know the cause
					die("Error reading from uplink %s:%s (%s)\n", uplink->remote_name, uplink->service, strerror(errno));
			}
		} else if (amount == 0) { // 0 means socket closed
			ulog(LLOG_WARN, "Remote closed the uplink %s:%s, reconnecting\n", uplink->remote_name, uplink->service);
CLOSED:
			assert(!uplink->reconnect_scheduled);
			uplink->reconnect_id = loop_timeout_add(uplink->loop, uplink->reconnect_timeout / 1000, NULL, uplink, reconnect_now);
			uplink->reconnect_scheduled = true;
			uplink_disconnect(uplink, false);
			return; // We are done with this socket.
		} else {
			uplink->seen_data = true;
			uplink->buffer_pos += amount;
			uplink->size_rest -= amount;
			if (uplink->size_rest == 0)
				handle_buffer(uplink);
		}
	}
}

struct uplink *uplink_create(struct loop *loop) {
	ulog(LLOG_INFO, "Creating uplink\n");
	struct mem_pool *permanent_pool = loop_permanent_pool(loop);
	struct uplink *result = mem_pool_alloc(permanent_pool, sizeof *result);
	*result = (struct uplink) {
		.uplink_read = uplink_read,
		.loop = loop,
		.buffer_pool = loop_pool_create(loop, NULL, mem_pool_printf(loop_temp_pool(loop), "Buffer pool for uplink")),
		.fd = -1
	};
	loop_uplink_set(loop, result);
	return result;
}

void uplink_configure(struct uplink *uplink, const char *remote_name, const char *service, const char *login, const char *password, const char *cert) {
	bool same =
		uplink->remote_name && strcmp(uplink->remote_name, remote_name) == 0 &&
		uplink->service && strcmp(uplink->service, service) == 0 &&
		uplink->cert && strcmp(uplink->cert, cert) == 0 &&
		(uplink->login == login || (uplink->login && strcmp(uplink->login, login) == 0)) &&
		(uplink->password == password || (uplink->password && strcmp(uplink->password, password)) == 0);
	// Set the new remote endpoint
	uplink->remote_name = remote_name;
	uplink->service = service;
	uplink->login = login;
	uplink->password = password;
	uplink->cert = cert;
	// If it is the same, we don't need to reconnect (but we need to store the new pointers, the old might die soon)
	if (same) {
		ulog(LLOG_DEBUG, "Not changing remote uplink as it is the same\n");
		return;
	}
	ulog(LLOG_INFO, "Changing remote uplink address to %s:%s\n", remote_name, service);
	// Reconnect
	if (!uplink->reconnect_scheduled) {
		uplink->reconnect_id = loop_timeout_add(uplink->loop, 0, NULL, uplink, reconnect_now);
		uplink->reconnect_scheduled = true;
	}
	uplink_disconnect(uplink, false);
}

void uplink_destroy(struct uplink *uplink) {
	ulog(LLOG_INFO, "Destroying uplink to %s:%s\n", uplink->remote_name, uplink->service);
	// The memory pools get destroyed by the loop, we just close the socket, if any.
	uplink_disconnect(uplink, true);
}

static bool buffer_send(struct uplink *uplink, const uint8_t *buffer, size_t size, int flags) {
	while (size > 0) {
		ssize_t amount = send(uplink->fd, buffer, size, MSG_NOSIGNAL | flags);
		if (amount == -1) {
			switch (errno) {
				case EINTR:
					// Just interrupt called during send. Retry.
					ulog(LLOG_WARN, "EINTR during send to %s:%s\n", uplink->remote_name, uplink->service);
					continue;
				case ECONNRESET:
				case EPIPE:
					// Lost connection. Reconnect.
					assert(!uplink->reconnect_scheduled);
					uplink->reconnect_id = loop_timeout_add(uplink->loop, 0, NULL, uplink, reconnect_now);
					uplink->reconnect_scheduled = true;
					uplink_disconnect(uplink, false);
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
	if (uplink->fd == -1)
		return false; // Not connected, we can't send.
	// The +1 is for the type sent directly after the length
	size_t head_len = sizeof(uint32_t) + 1;
	uint8_t head_buffer[head_len];
	uint32_t head_size = htonl(size + 1);
	memcpy(head_buffer, &head_size, sizeof head_size);
	head_buffer[head_len - 1] = type;
	return buffer_send(uplink, head_buffer, head_len, MSG_MORE) && buffer_send(uplink, data, size, 0);
}

bool uplink_plugin_send_message(struct context *context, const void *data, size_t size) {
	const char *name = loop_plugin_get_name(context);
	ulog(LLOG_DEBUG, "Sending message of size %zu from plugin %s\n", size, name);
	uint32_t name_length = strlen(name);
	uint32_t length = sizeof name_length + name_length + size;
	uint8_t *buffer = mem_pool_alloc(context->temp_pool, length);
	uint8_t *buffer_pos = buffer;
	size_t buffer_len = length;
	uplink_render_string(name, name_length, &buffer_pos, &buffer_len);
	memcpy(buffer_pos, data, size);
	return uplink_send_message(context->uplink, 'R', buffer, length);
}

void uplink_realloc_config(struct uplink *uplink, struct mem_pool *pool) {
	if (uplink->remote_name)
		uplink->remote_name = mem_pool_strdup(pool, uplink->remote_name);
	if (uplink->service)
		uplink->service = mem_pool_strdup(pool, uplink->service);
	if (uplink->login)
		uplink->login = mem_pool_strdup(pool, uplink->login);
	if (uplink->password)
		uplink->password = mem_pool_strdup(pool, uplink->password);
}

const uint8_t *uplink_address(struct uplink *uplink) {
	if (uplink->addr_len)
		return uplink->address;
	else
		return NULL;
}

size_t uplink_addr_len(struct uplink *uplink) {
	return uplink->addr_len;
}

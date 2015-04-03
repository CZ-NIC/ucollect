/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "telnet.h"
#include "main.h"

#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/context.h"
#include "../../core/loop.h"

#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>

enum expect {
	EXPECT_NONE,
	EXPECT_CMD,
	EXPECT_OPCODE,
	EXPECT_PARAMS,
	EXPECT_PARAMS_END,
	EXPECT_LF
};

enum command {
	CMD_SE = 240,
	CMD_NOP = 241,
	CMD_DM = 242,
	CMD_BREAK = 243,
	CMD_IP = 244,
	CMD_AO = 245,
	CMD_AYT = 246,
	CMD_EC = 247,
	CMD_EL = 248,
	CMD_GA = 249,
	CMD_SB = 250,
	CMD_WILL = 251,
	CMD_WONT = 252,
	CMD_DO = 253,
	CMD_DONT = 254,
	CMD_IAC = 255
};

enum position {
	WANT_LOGIN,
	WANT_PASSWORD,
	WAIT_DENIAL
};

const size_t denial_timeout = 1000;
const size_t max_attempts = 3;

struct conn_data {
	int fd;
	enum expect expect; // Local context - like expecting a command specifier as the next character, etc.
	enum command neg_verb; // What was the last verb used for option negotiation
	enum position position; // Global state
	bool protocol_error; // Was there error in the protocol, causing it to close?
	const char *close_reason;
	size_t denial_timeout;
	size_t attempts; // Number of attempts the other side tried
	struct fd_tag *tag;
};

struct conn_data *telnet_conn_alloc(struct context *context, struct fd_tag *tag, struct mem_pool *pool, struct server_data *server) {
	(void)context;
	(void)server;
	struct conn_data *result = mem_pool_alloc(pool, sizeof *result);
	ulog(LLOG_DEBUG, "Allocated telnet connection %p for tag %p\n", (void *)result, (void *)tag);
	memset(result, 0, sizeof *result);
	return result;
}

static bool send_all(struct conn_data *conn, const uint8_t *data, size_t amount) {
	while (amount) {
		ssize_t sent = send(conn->fd, data, amount, MSG_NOSIGNAL);
		if (sent == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			ulog(LLOG_DEBUG, "Telnet send error: %s\n", strerror(errno));
			if (!conn->close_reason)
				conn->close_reason = strerror(errno);
			return false;
		}
		data += sent;
		amount -= sent;
	}
	return true;
}

static bool ask_for(struct context *context, struct conn_data *conn, const char *prompt) {
	size_t len = strlen(prompt);
	uint8_t *msg = mem_pool_alloc(context->temp_pool, len+4); // ':', ' ', IAC, GA
	memcpy(msg, prompt, len);
	msg[len] = ':';
	msg[len+1] = ' ';
	msg[len+2] = CMD_IAC;
	msg[len+3] = CMD_GA;
	return send_all(conn, msg, len + 4);
}

static void do_close(struct context *context, struct conn_data *conn, bool error) {
	if (conn->position == WAIT_DENIAL)
		loop_timeout_cancel(context->loop, conn->denial_timeout);
	conn_closed(context, conn->tag, error, conn->close_reason);
}

void telnet_conn_set_fd(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn, int fd) {
	(void)context;
	(void)server;
	conn->expect = EXPECT_NONE;
	conn->protocol_error = false;
	conn->position = WANT_LOGIN;
	conn->fd = fd;
	ulog(LLOG_DEBUG, "Accepted to telnet connection %p on tag %p, fd %d\n", (void *)conn, (void *)tag, fd);
	if (!ask_for(context, conn, "login"))
		do_close(context, conn, true);
	conn->tag = tag;
	conn->attempts = 0;
	conn->close_reason = NULL;
}

static bool protocol_error(struct context *context, struct conn_data *conn, const char *message) {
	conn->protocol_error = true;
	if (!conn->close_reason)
		conn->close_reason = message;
	ulog(LLOG_DEBUG, "Telnet protocol error %s\n", message);
	size_t len = strlen(message);
	uint8_t *message_eol = mem_pool_alloc(context->temp_pool, len + 4); // 2 more for CR LF, 2 more for IAC GA
	memcpy(message_eol, message, len);
	message_eol[len] = '\r';
	message_eol[len+1] = '\n';
	message_eol[len+2] = CMD_IAC;
	message_eol[len+3] = CMD_GA;
	send_all(conn, message_eol, len + 4);
	return false;
}

static void send_denial(struct context *context, void *data, size_t id) {
	(void)id;
	struct conn_data *conn = data;
	conn->position = WANT_LOGIN;
	const char *wrong = "Login incorrect\n";
	if (!send_all(conn, (const uint8_t *)wrong, strlen(wrong))) {
		do_close(context, conn, true);
		return;
	}
	if (++ conn->attempts == max_attempts) {
		conn->close_reason = "Attempts";
		do_close(context, conn, false);
		return;
	}
	if (!ask_for(context, conn, "login")) {
		do_close(context, conn, true);
		return;
	}
}

static bool process_line(struct context *context, struct fd_tag *tag, struct conn_data *conn) {
	(void)tag;
	switch (conn->position) {
		case WANT_LOGIN:
			if (!ask_for(context, conn, "password"))
				return false;
			conn->position = WANT_PASSWORD;
			break;
		case WANT_PASSWORD:
			conn->position = WAIT_DENIAL;
			conn->denial_timeout = loop_timeout_add(context->loop, denial_timeout, context, conn, send_denial);
			conn_log_attempt(context, tag);
			break;
		case WAIT_DENIAL:
			ulog(LLOG_DEBUG, "Data when expecting none on telnet connection %p on tag %p with fd %d\n", (void *)conn, (void *)tag, conn->fd);
	}
	return true;
}

static bool cmd_handle(struct context *context, struct conn_data *conn, uint8_t cmd) {
	switch (cmd) {
		case CMD_SE: // Subnegotiation end - this should not be here, it should appear in EXPECT_PARAMS_END
			return protocol_error(context, conn, "Unexpected SE");
		case CMD_NOP: // NOP
		case CMD_DM: // Data Mark - not implemented and ignored
		case CMD_BREAK: // Break - just strange character
		case CMD_AO: // Abort output - not implemented
		case CMD_AYT: // Are You There - not implemented
		case CMD_EC: // Erase character - ignored
		case CMD_EL: // Erase Line - ignored
		case CMD_GA: // Go Ahead - not interesting to us
			conn->expect = EXPECT_NONE;
			return true;
		case CMD_SB: // Subnegotiation parameters
			conn->expect = EXPECT_PARAMS;
			return true;
		case CMD_WILL:
		case CMD_WONT:
		case CMD_DO:
		case CMD_DONT:
			conn->expect = EXPECT_OPCODE;
			conn->neg_verb = cmd;
			return true;
		case CMD_IP: // Interrupt process - abort connection
			return protocol_error(context, conn, "Interrupted");
		default:
			return protocol_error(context, conn, mem_pool_printf(context->temp_pool, "Unknown telnet command %hhu\n", cmd));
	}
}

static bool char_handle(struct context *context, struct fd_tag *tag, struct conn_data *conn, uint8_t ch) {
	switch (conn->expect) {
		case EXPECT_NONE:
			break;
		case EXPECT_CMD:
			return cmd_handle(context, conn, ch);
		case EXPECT_OPCODE: {
			if (conn->neg_verb == CMD_WILL || conn->neg_verb == CMD_DO) {
				// Refuse the option
				uint8_t cmd = (conn->neg_verb ^ (CMD_WILL ^ CMD_DO)) + 1; // WILL->DON'T, DO->WON'T
				uint8_t message[3] = { CMD_IAC, cmd, ch };
				if (!send_all(conn, message, sizeof message))
					return false;
			} // else - it's off, so this is OK, no reaction
			conn->expect = EXPECT_NONE;
			return true;
		}
		case EXPECT_PARAMS:
			if (ch == CMD_IAC)
				conn->expect = EXPECT_PARAMS_END;
			return true;
		case EXPECT_PARAMS_END:
			if (ch == CMD_SE)
				conn->expect = EXPECT_NONE;
			else
				conn->expect = EXPECT_PARAMS;
			return true;
		case EXPECT_LF:
			if (ch == '\n')
				if (!process_line(context, tag, conn))
					return false;
			conn->expect = EXPECT_NONE;
			return true;
		default:
			assert(0); // Invalid expect state
	}
	// We are in a normal mode, decide if we see anything special
	switch (ch) {
		case CMD_IAC:
			conn->expect = EXPECT_CMD;
			break;
		case '\r':
			conn->expect = EXPECT_LF;
			break;
		// Otherwise - just some data
	}
	return true;
}

void telnet_data(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn) {
	(void)server;
	const size_t block = 1024;
	void *buffer = mem_pool_alloc(context->temp_pool, block);
	ssize_t amount = recv(conn->fd, buffer, block, MSG_DONTWAIT);
	bool error = false;
	switch (amount) {
		case -1: // Error
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				return;
			ulog(LLOG_DEBUG, "Error on telnet connection %p on tag %p with fd %d: %s\n", (void *)conn, (void *)tag, conn->fd, strerror(errno));
			conn->close_reason = strerror(errno);
			error = true;
			// No break - fall through
		case 0: // Close
			ulog(LLOG_DEBUG, "Closed telnet connection %p/%p/%d\n", (void *)conn, (void *)tag, conn->fd);
			if (!conn->close_reason)
				conn->close_reason = "Closed";
			do_close(context, conn, error);
			return;
		default:
			break;
	}
	// OK, we have data, all unusual cases handled above
	ulog(LLOG_DEBUG, "Telnet data on connection %p/%p/%d: %s\n", (void *)conn, (void *)tag, conn->fd, mem_pool_hex(context->temp_pool, buffer, amount));
	const uint8_t *data = buffer;
	for (ssize_t i = 0; i < amount; i ++)
		if (!char_handle(context, tag, conn, data[i])) {
			do_close(context, conn, conn->protocol_error);
			return;
		}
}

/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2016 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "websrv.h"
#include "main.h"
#include "base64.h"

#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/context.h"

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

static const char *response_malformed =
"HTTP/1.1 400 Bad Request\r\n"
"Content-Type: text/html; charset=UTF-8\r\n"
"Content-Encoding: UTF-8\r\n"
"Content-Length: 141\r\n"
"\r\n"
"<html>\r\n"
"<head><title>400 Bad Request</title></head>\r\n"
"<body><h1>400 Bad Request</h1><p>I couldn't understand you, sorry.</p></body>\r\n"
"</html>\r\n";

static const char *response_unauth =
"HTTP/1.1 401 Unauthorized\r\n"
"Content-Type: text/html; charset=UTF-8\r\n"
"Content-Encoding: UTF-8\r\n"
"Content-Length: 164\r\n"
"WWW-Authenticate: Basic realm=\"Admin interface\"\r\n"
"\r\n"
"<html>\r\n"
"<head><title>401 Unauthorized</title></head>\r\n"
"<body><h1>401 Unauthorized</h1><p>You need to provide the correct username and password.</p></body>\r\n"
"</html>\r\n";

/*
 * As we use this code for both http server and http proxy, we
 * put some parameters here to be used to influence which one.
 */
struct server_data {
	const char *malformed;
	const char *unauth;
	const char *auth_header;
};

struct server_data *alloc_websrv(struct context *context __attribute__((unused)), struct fd_tag *tag __attribute__((unused)), struct mem_pool *pool, const struct server_desc *desc __attribute__((unused))) {
	struct server_data *result = mem_pool_alloc(pool, sizeof *result);
	*result = (struct server_data) {
		.malformed = response_malformed,
		.unauth = response_unauth,
		.auth_header = "Authorization"
	};
	return result;
}

#define LINE_MAX 512
#define MAX_HEADER 256

struct conn_data {
	int fd;
	char line_data[LINE_MAX];
	char *line;
	char *close_reason;
	char method[MAX_HEADER];
	char url[MAX_HEADER];
	char host[MAX_HEADER];
	char username[MAX_HEADER];
	char password[MAX_HEADER];
	bool error;
	bool has_host;
	bool has_auth;
	struct fd_tag *tag;
};

struct conn_data *http_conn_alloc(struct context *context __attribute__((unused)), struct fd_tag *tag, struct mem_pool *pool, struct server_data *server __attribute__((unused))) {
	struct conn_data *result = mem_pool_alloc(pool, sizeof *result);
	ulog(LLOG_DEBUG, "Allocated http connection %p for tag %p\n", (void *)result, (void *)tag);
	memset(result, 0, sizeof *result);
	return result;
}

static void line_reset(struct conn_data *conn) {
	conn->line = conn->line_data;
}

void http_conn_set_fd(struct context *context __attribute__((unused)), struct fd_tag *tag, struct server_data *server __attribute__((unused)), struct conn_data *conn, int fd) {
	memset(conn, 0, sizeof *conn);
	conn->fd = fd;
	ulog(LLOG_DEBUG, "Accepted http connection %p on tag %p, fd %d\n", (void *)conn, (void *)tag, fd);
	conn->tag = tag;
	line_reset(conn);
}

static void do_close(struct context *context, struct conn_data *conn, bool error) {
	conn_closed(context, conn->tag, error, conn->close_reason);
}

static void response_send(struct conn_data *conn, const char *response) {
	size_t len = strlen(response);
	while (*response) {
		ssize_t sent = send(conn->fd, response, len, MSG_NOSIGNAL);
		if (sent == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				continue;
			ulog(LLOG_DEBUG, "HTTP send error: %s\n", strerror(errno));
			conn->close_reason = strerror(errno);
			return;
		}
		response += sent;
		len -= sent;
	}
}

static bool line_handle(struct context *context, struct conn_data *data, struct server_data *server) {
	// Terminate the line (there must be at least 1 byte empty by the check at char_handle)
	sanity(data->line - data->line_data < LINE_MAX, "Not enough space for http line terminator\n");
	*data->line = '\0';
	const char *l = data->line_data;
	if (*data->method) {
		if (*l) {
			// We've read the first line. This is some kind of header.
			char *colon = index(l, ':');
			// Just a common snippet of code to report protocol violation
#define MALF(REASON) do { \
	data->error = true; \
	data->close_reason = (REASON); \
	response_send(data, server->malformed); \
	return false; \
} while (0)
			if (!colon)
				MALF("Malformed header");
			// Terminate the header name
			*(colon ++) = '\0';
			// Find where the header data begins
			while (*colon == ' ' || *colon == '\t')
				colon ++;
			if (strcasecmp(l, "Host") == 0) {
				strncpy(data->host, colon, MAX_HEADER);
				data->host[MAX_HEADER - 1] = '\0';
				data->has_host = true;
			} else if (strcasecmp(l, server->auth_header) == 0) {
				char *space = index(colon, ' ');
				if (!space)
					MALF("Malformed auth");
				// Decode the base64. Don't worry about that space, it's invalid char and will be skipped
				base64_decode_inplace((uint8_t *)space);
				char *colon = index(space, ':');
				if (!colon)
					MALF("Malformed auth");
				*colon = '\0';
				strncpy(data->username, space, MAX_HEADER);
				data->username[MAX_HEADER - 1] = '\0';
				colon ++;
				strncpy(data->password, colon, MAX_HEADER);
				data->password[MAX_HEADER - 1] = '\0';
				data->has_auth = true;
			}
		} else {
			// Empty line. OK, let's roll. Log the attempt, send a reply.
			conn_log_attempt(context, data->tag, data->has_auth ? data->username : NULL, data->has_auth ? data->password : NULL, data->method, data->has_host ? data->host : NULL, data->url);
			// Erase all the strings
			*data->username = *data->password = *data->host = *data->method = *data->url = '\0';
			data->has_auth = data->has_host = false;
			response_send(data, server->unauth);
			// As we don't parse any possible request body, we just terminate the connection to make it easier for us. That is legal.
			data->close_reason = "Completed";
			return false;
		}
	} else {
		// The first line. Split it into: GET URL HTTP/1.1
		char *space = index(l, ' ');
		if (!space)
			MALF("Missing URL");
		*space = '\0';
		strncpy(data->method, l, MAX_HEADER);
		data->method[MAX_HEADER - 1] = '\0';
		// There must be at least that NULL byte we put there at the beginning of this function, so it's OK
		l = space + 1;
		space = index(l, ' ');
		if (!space)
			MALF("Missing protocol");
		*space = '\0';
		strncpy(data->url, l, MAX_HEADER);
		data->url[MAX_HEADER - 1] = '\0';
	}
	line_reset(data);
	return true;
}

static bool char_handle(struct context *context, struct conn_data *conn, struct server_data *server, uint8_t ch) {
	switch (ch) {
		case '\r':
			// We simply ignore CR and wait for LF (we don't validate they go after each other)
			break;
		case '\n':
			// LF came ‒ handle the whole accumulated line
			return line_handle(context, conn, server);
		default:
			// Just accumulate the data of the line
			if (conn->line && conn->line - conn->line_data + 1 < LINE_MAX)
				*(conn->line ++) = ch;
			break;
	}
	return true;
}

void http_data(struct context *context, struct fd_tag *tag, struct server_data *server, struct conn_data *conn) {
	const size_t block = 1024;
	void *buffer = mem_pool_alloc(context->temp_pool, block);
	ssize_t amount = recv(conn->fd, buffer, block, MSG_DONTWAIT);
	bool error = false;
	switch (amount) {
		case -1: // Error
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				// Try again (we'll be called by the main loop)
				return;
			ulog(LLOG_DEBUG, "Error on http connection %p on tag %p with fd %d: %s\n", (void *)conn, (void *)tag, conn->fd, strerror(errno));
			conn->close_reason = strerror(errno);
			error = true;
			// No break - fall through
		case 0: // Close
			ulog(LLOG_DEBUG, "Closed http connection %p/%p/%d\n", (void *)conn, (void *)tag, conn->fd);
			if (!conn->close_reason)
				conn->close_reason = "Closed";
			do_close(context, conn, error);
			return;
		default:
			break;
	}
	// OK, we have data, all unusual cases handled above
	ulog(LLOG_DEBUG, "Http data on connection %p/%p/%d: %s\n", (void *)conn, (void *)tag, conn->fd, mem_pool_hex(context->temp_pool, buffer, amount));
	const uint8_t *data = buffer;
	for (ssize_t i = 0; i < amount; i ++)
		if (!char_handle(context, conn, server, data[i])) {
			do_close(context, conn, conn->error);
			return;
		}
}

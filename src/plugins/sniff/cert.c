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

#include "cert.h"
#include "parse.h"

#include "../../core/util.h"
#include "../../core/uplink.h"
#include "../../core/mem_pool.h"
#include "../../core/context.h"

#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

static const char *cert_program =
#include <sniff-cert.inc>
;

struct target {
	bool want_cert; // If not cert, then fingerprint only.
	bool want_chain;
	bool want_details;
	bool want_params;
};

static const uint8_t STARTTLS_PROTO_MASK = 1 | 2 | 4; // First 3 bits are the starttls protocol
static const char *tls_proto[] = {
	"",
	"smtp",
	"pop3",
	"imap",
	"ftp",
	"xmpp",
	NULL,
	NULL
};
static const uint8_t WANT_CERT = 1 << 3;
static const uint8_t WANT_CHAIN = 1 << 4;
static const uint8_t WANT_DETAILS = 1 << 5;
static const uint8_t WANT_PARAMS = 1 << 6;
static const uint8_t MORE_FLAGS = 1 << 7;

static bool cert_parse(struct mem_pool *task_pool, struct mem_pool *tmp_pool, struct target *target, char **args, const uint8_t **message, size_t *message_size, size_t index) {
	(void) task_pool;
	size_t header = sizeof(uint8_t) + sizeof(uint16_t);
	if (*message_size < header) {
		ulog(LLOG_ERROR, "Message too short, SSL host %zu incomplete\n", index);
		return false;
	}
	uint8_t flags = **message;
	uint16_t port;
	memcpy(&port, *message + sizeof flags, sizeof port);
	*message += header;
	*message_size -= header;
	port = ntohs(port);
	if (flags & MORE_FLAGS) {
		ulog(LLOG_ERROR, "More SSL flags sent for host %zu, but I don't know how to parse\n", index);
		return false;
	}
	target->want_cert = flags & WANT_CERT;
	target->want_chain = flags & WANT_CHAIN;
	target->want_details = flags & WANT_DETAILS;
	target->want_params = flags & WANT_PARAMS;
	args[0] = uplink_parse_string(tmp_pool, message, message_size);
	if (!args[0]) {
		ulog(LLOG_ERROR, "Hostname of SSL host %zu is broken\n", index);
		return false;
	}
	args[1] = mem_pool_printf(tmp_pool, "%u", (unsigned) port);
	const char *tls = tls_proto[flags & STARTTLS_PROTO_MASK];
	if (!tls) {
		ulog(LLOG_ERROR, "Unknown StartTLS protocol %u on host %zu\n", (unsigned) (flags & STARTTLS_PROTO_MASK), index);
		return false;
	}
	args[2] = mem_pool_strdup(tmp_pool, tls);
	return true;
}

struct task_data *start_cert(struct context *context, struct mem_pool *pool, const uint8_t *message, size_t message_size, int *output, pid_t *pid) {
	return input_parse(context, pool, message, message_size, output, pid, cert_program, "sslcert", 3, sizeof(struct target), cert_parse);
}

static char *block(char **input, const char *end) {
	char *orig = *input;
	char *found = strstr(*input, end);
	if (found) {
		size_t len = strlen(end);
		for (size_t i = 0; i < len; i ++)
			found[i] = '\0';
		*input = found + len;
		return orig;
	} else {
		return NULL;
	}
}

static const char *host_block_end = "-----END HOST-----\n";
static const char *host_block_begin = "-----BEGIN HOST-----\n";
static const char *mark_begin = "-----";
static const char *mark_end = "-----\n";

struct parsed_cert {
	struct parsed_cert *next;
	const char *cert;
	const char *fingerprint;
	const char *name;
};

struct parsed_ssl {
	const char *cipher;
	const char *proto;
	size_t count;
	struct parsed_ssl *next;
	struct parsed_cert *head, *tail;
};

struct parsed {
	size_t count;
	struct parsed_ssl *head, *tail;
};

#define LIST_NODE struct parsed_cert
#define LIST_BASE struct parsed_ssl
#define LIST_COUNT count
#define LIST_NAME(X) parsed_cert_##X
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#include "../../core/link_list.h"

#define LIST_NODE struct parsed_ssl
#define LIST_BASE struct parsed
#define LIST_COUNT count
#define LIST_NAME(X) parsed_ssl_##X
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#include "../../core/link_list.h"

static bool block_parse(struct mem_pool *pool, char *text, struct parsed_ssl *dest) {
	dest->cipher = NULL;
	dest->proto = NULL;
	dest->head = NULL;
	dest->tail = NULL;
	dest->count = 0;
	struct parsed_cert *cert = NULL;
	const char *prefix = block(&text, host_block_begin);
	if (!prefix) {
		ulog(LLOG_ERROR, "Host block begin not found\n");
		return false;
	}
	if (*prefix) {
		ulog(LLOG_ERROR, "Data before block begin\n");
		return false;
	}
	prefix = block(&text, mark_begin);
	if (!prefix) { // No more data in the block ‒ likely we couldn't connect to the host
		ulog(LLOG_DEBUG, "Host block empty\n");
		return true;
	}
	if (*prefix) {
		ulog(LLOG_ERROR, "Stray data after block start\n");
		return false;
	}
	const char *name;
	while (*text && (name = block(&text, mark_end))) {
		char *content = text;
		block(&text, mark_begin); // Find the end of the content. The begin of the next marker might be missing (on the last one)
		if (strcmp(name, "CIPHER") == 0)
			dest->cipher = content;
		else if (strcmp(name, "PROTOCOL") == 0)
			dest->proto = content;
		else if (strcmp(name, "BEGIN CERTIFICATE") == 0) {
			cert = parsed_cert_append_pool(dest, pool);
			cert->cert = content;
			cert->fingerprint = NULL;
			cert->name = NULL;
		} else if (strcmp(name, "END CERTIFICATE") == 0) {
			// OK, ignore.
		} else if (strcmp(name, "FINGERPRINT") == 0) {
			assert(cert);
			cert->fingerprint = content;
		} else if (strcmp(name, "NAME") == 0) {
			assert(cert);
			cert->name = content;
		}
	}
	return true;
}

const uint8_t *finish_cert(struct context *context, struct task_data *data, uint8_t *output, size_t output_size, size_t *result_size, bool *ok) {
	// TODO: Unify code
#define FAIL(CODE, MESSAGE) do { *result_size = 1; *ok = false; ulog(LLOG_INFO, "Sending error cert response %s: %s\n", CODE, MESSAGE); return (const uint8_t *)(CODE); } while (0)
	if (!data->input_ok)
		FAIL("I", "Invalid certificate input");
	if (!data->system_ok)
		FAIL("F", "Failed to run certificate command");
	if (!output)
		FAIL("P", "Pipe error reading certificate output");
	if (data->target_count && !output_size)
		FAIL("R", "Read error while getting certificate output");
	char *text = (char *) output;
	char *host;
	struct parsed parsed = { .count = 0 };
	// Parse the text into parts
	while ((host = block(&text, host_block_end))) {
		struct parsed_ssl *ssl = parsed_ssl_append_pool(&parsed, context->temp_pool);
		if (!block_parse(context->temp_pool, host, ssl))
			FAIL("B", mem_pool_printf(context->temp_pool, "Error parsing block %zu", parsed.count));
	}
	if (*text)
		FAIL("E", "Unexpected end of output");
	if (parsed.count != data->target_count)
		FAIL("C", mem_pool_printf(context->temp_pool, "Wrong number of outputs, got %zu and expected %zu", parsed.count, data->target_count));
	size_t target_size = 0;
	size_t i = 0;
	// Compute size of output
	LFOR(parsed_ssl, ssl, &parsed) {
		target_size += 1;
		if (ssl->count && data->targets[i].want_params)
			target_size += 8 + strlen(ssl->cipher) + strlen(ssl->proto);
		LFOR(parsed_cert, cert, ssl) {
			target_size += 4 + strlen(data->targets[i].want_cert ? cert->cert : cert->fingerprint);
			if (data->targets[i].want_details)
				target_size += 4 + strlen(cert->name);
			if (!data->targets[i].want_chain) {
				// We take only 1 cert, no matter if there's more.
				ssl->count = 1;
				cert->next = NULL;
				ssl->tail = cert;
				break;
			}
		}
		i ++;
	}
	// Prepare output
	*result_size = target_size;
	*ok = true;
	uint8_t *result = mem_pool_alloc(context->temp_pool, target_size);
	uint8_t *pos = result;
	i = 0;
	LFOR(parsed_ssl, ssl, &parsed) {
		assert(target_size);
		*(pos ++) = ssl->count;
		target_size --;
		if (ssl->count && data->targets[i].want_params) {
			uplink_render_string(ssl->cipher, strlen(ssl->cipher), &pos, &target_size);
			uplink_render_string(ssl->proto, strlen(ssl->proto), &pos, &target_size);
		}
		LFOR(parsed_cert, cert, ssl) {
			const char *payload = data->targets[i].want_cert ? cert->cert : cert->fingerprint;
			uplink_render_string(payload, strlen(payload), &pos, &target_size);
			if (data->targets[i].want_details)
				// TODO: Date too, please
				uplink_render_string(cert->name, strlen(cert->name), &pos, &target_size);
		}
		i ++;
	}
	assert(target_size == 0);
	return result;
}

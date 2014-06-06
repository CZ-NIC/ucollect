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

#include <string.h>
#include <arpa/inet.h>

const char *cert_program =
#include <sniff-cert.inc>
;

struct target {
	bool want_cert; // If not cert, then fingerprint only.
	bool want_chain;
	bool want_name;
	bool want_params;
};

const uint8_t STARTTLS_PROTO_MASK = 1 | 2 | 4; // First 3 bits are the starttls protocol
const char *tls_proto[] = {
	"",
	"smtp",
	"pop3",
	"imap",
	"ftp",
	"xmpp",
	NULL,
	NULL
};
const uint8_t WANT_CERT = 1 << 3;
const uint8_t WANT_CHAIN = 1 << 4;
const uint8_t WANT_NAME = 1 << 5;
const uint8_t WANT_PARAMS = 1 << 6;
const uint8_t MORE_FLAGS = 1 << 7;

static bool cert_parse(struct mem_pool *task_pool, struct mem_pool *tmp_pool, struct target *target, char **args, const uint8_t **message, size_t *message_size, size_t index) {
	(void) task_pool;
	size_t header = sizeof(uint8_t) + sizeof(uint16_t);
	if (*message_size < header) {
		ulog(LLOG_ERROR, "Message too short, SSL host %zu incomplete\n", index);
		return false;
	}
	uint8_t flags = **message;
	uint16_t port;
	memcpy(&port, message + sizeof flags, sizeof port);
	port = ntohs(port);
	if (flags & MORE_FLAGS) {
		ulog(LLOG_ERROR, "More SSL flags sent for host %zu, but I don't know how to parse\n", index);
		return false;
	}
	target->want_cert = flags & WANT_CERT;
	target->want_chain = flags & WANT_CHAIN;
	target->want_name = flags & WANT_NAME;
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

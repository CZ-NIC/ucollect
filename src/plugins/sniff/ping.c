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

#include "ping.h"
#include "fork.h"

#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/context.h"
#include "../../core/uplink.h"

#include <arpa/inet.h>
#include <string.h>

#define PINGER_PROGRAM "ucollect-sniff-ping"

struct task_data {
	bool input_ok;
	bool system_ok;
	size_t host_count;
	size_t *ping_counts;
};

static bool host_parse(struct mem_pool *tmp_pool, char **dest, struct task_data *data, size_t host_num, const uint8_t **message, size_t *message_size) {
	size_t header = sizeof(char) + sizeof(uint8_t) + sizeof(uint16_t);
	if (*message_size < header) {
		ulog(LLOG_ERROR, "Message too short, host %zu incomplete\n", host_num);
		return false;
	}
	char proto = **message;
	uint8_t count = (*message)[sizeof proto];
	uint16_t size;
	memcpy(&size, *message + sizeof proto + sizeof count, sizeof size);
	size = ntohs(size);
	*message += header;
	*message_size -= header;
	char *host = uplink_parse_string(tmp_pool, message, message_size);
	if (!host) {
		ulog(LLOG_ERROR, "Hostname of host %zu is broken\n", host_num);
		return false;
	}
	if (proto != '4' && proto != '6' && proto != 'X') {
		ulog(LLOG_ERROR, "Unknown ping protocol %c on host %zu\n", proto, host_num);
		return false;
	}
	dest[0] = mem_pool_printf(tmp_pool, "%c", proto);
	dest[1] = mem_pool_printf(tmp_pool, "%d", count);
	dest[2] = mem_pool_printf(tmp_pool, "%d", size);
	dest[3] = host;
	data->ping_counts[host_num] = count;
	return false;
}

struct task_data *start_ping(struct context *context, struct mem_pool *pool, const uint8_t *message, size_t message_size, int *output, pid_t *pid) {
	*output = 0; // Not running yet
	struct task_data *data = mem_pool_alloc(pool, sizeof *data);
	*data = (struct task_data) {
		.input_ok = true,
		.system_ok = true
	};
#define CHECK(cond, message, ...) if (!(cond)) {\
		ulog(LLOG_ERROR, message, __VA_ARGS__); \
		data->input_ok = false; \
		return data; \
	}
	uint16_t host_count;
	CHECK(message_size >= sizeof host_count, "Ping input broken: Message too short to contain even the number of hosts to ping (%zu bytes)\n", message_size);
	memcpy(&host_count, message, sizeof host_count);
	message += sizeof host_count;
	message_size -= sizeof host_count;
	host_count = ntohs(host_count);
	char **argv = mem_pool_alloc(context->temp_pool, (2 + 4 * host_count) * sizeof *argv);
	argv[0] = PINGER_PROGRAM;
	argv[1 + 4 * host_count] = NULL;
	data->host_count = host_count;
	data->ping_counts = mem_pool_alloc(pool, host_count * sizeof *data->ping_counts);
	for (size_t i = 0; i < host_count; ++ i)
		if (!host_parse(context->temp_pool, argv + 1 + 4 * i, data, i, &message, &message_size)) {
			data->input_ok = false;
			return data;
		}
	data->system_ok = fork_task(PINGER_PROGRAM, argv, "pinger", output, pid);
	return data;
}

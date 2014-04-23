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

#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/context.h"

#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define PINGER_PROGRAM "ucollect-sniff-ping"

struct task_data {
	bool input_ok;
	bool system_ok;
	size_t host_count;
	size_t *ping_counts;
};

static bool host_parse(char **dest, struct task_data *data, const uint8_t **message, size_t *message_size) {
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
		if (!host_parse(argv + 1 + 4 * i, data, &message, &message_size)) {
			data->input_ok = false;
			return data;
		}
	int pipes[2];
	if (pipe(pipes) == -1) {
		ulog(LLOG_ERROR, "Couldn't create pinger pipes: %s\n", strerror(errno));
		data->system_ok = false;
		return data;
	}
	pid_t new_pid = fork();
	if (new_pid == -1) {
		ulog(LLOG_ERROR, "Couldn't create pinger process: %s\n", strerror(errno));
		data->system_ok = false;
		if (close(pipes[0]) == -1)
			ulog(LLOG_ERROR, "Failed to close pinger read pipe: %s\n", strerror(errno));
		if (close(pipes[1]) == -1)
			ulog(LLOG_ERROR, "Failed to close pinger write pipe: %s\n", strerror(errno));
		return data;
	}
	if (new_pid == 0) { // We are the child now.
		if (close(pipes[0]) == -1)
			die("Failed to close pinger read pipe in child: %s\n", strerror(errno));
		if (dup2(pipes[1], 1) == -1)
			die("Failed to assign stdout of pinger: %s\n", strerror(errno));
		if (close(pipes[1]) == -1)
			die("Failed to close copy of pinger write pipe: %s\n", strerror(errno));
		execvp(PINGER_PROGRAM, argv);
		die("Failed to execute pinger: %s\n", strerror(errno));
	} else {
		if (close(pipes[1]) == -1)
			ulog(LLOG_ERROR, "Couldn't close pinger write pipe: %s\n", strerror(errno));
		ulog(LLOG_DEBUG, "Pinger started with FD %d and PID %d\n", pipes[0], (int) new_pid);
		*output = pipes[0];
		*pid = new_pid;
	}
	return data;
}

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

#include "parse.h"
#include "fork.h"

#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/context.h"

#include <string.h>
#include <arpa/inet.h>

struct task_data *input_parse(struct context *context, struct mem_pool *pool, const uint8_t *message, size_t message_size, int *output, pid_t *pid, const char *program, const char *name, size_t params_per_target, size_t target_size, task_parse_t task_parse) {
	*output = 0; // Not running yet
	struct task_data *data = mem_pool_alloc(pool, sizeof *data);
	*data = (struct task_data) {
		.input_ok = true,
		.system_ok = true
	};
	uint16_t target_count;
	if (message_size < sizeof target_count) {
		ulog(LLOG_ERROR, "%s input broken: Message too short to contain even the number of hosts (%zu bytes)\n", name, message_size);
		data->input_ok = false;
		return data;
	}
	memcpy(&target_count, message, sizeof target_count);
	message += sizeof target_count;
	message_size -= sizeof target_count;
	target_count = ntohs(target_count);
	char **argv = mem_pool_alloc(context->temp_pool, (6 + params_per_target * target_count) * sizeof *argv);
	argv[0] = "/bin/busybox";
	argv[1] = "ash";
	argv[2] = "-c";
	argv[3] = mem_pool_strdup(context->temp_pool, program);
	argv[4] = mem_pool_printf(context->temp_pool, "sniff-%s", name);
	argv[5 + params_per_target * target_count] = NULL;
	data->target_count = target_count;
	data->targets = mem_pool_alloc(pool, target_count * target_size);
	for (size_t i = 0; i < target_count; ++ i)
		if (!task_parse(pool, context->temp_pool, (struct target *)((uint8_t *) data->targets + i * target_size), argv + 5 + params_per_target * i, &message, &message_size, i)) {
			data->input_ok = false;
			return data;
		}
	data->system_ok = fork_task("/bin/busybox", argv, name, output, pid);
	return data;
}

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

#include "task.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/uplink.h"

#include <unistd.h>
#include <string.h>
#include <assert.h>

// Single running task.
struct task {
	struct task *next, *prev; // Link list.
	struct task_data *data; // Data of the task
	uint32_t id; // ID, just bytes copied from the request
	pid_t pid; // PID of the child performing the request
	int out; // FD of its stdout
	char *buffer; // Buffer where we put the output to be parsed
	size_t buffer_used, buffer_allocated;
};

struct user_data {
	struct mem_pool *pool; // Pool for temporary data for tasks. Will be flushed whenever there's no task running.
	struct task *first, *last; // Currently running tasks.
};

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.pool = loop_pool_create(context->loop, context, "Sniffer pool")
	};
}

static void cleanup(struct context *context) {
	// TODO
}

static void in_request(struct context *context, const uint8_t *data, size_t length) {
	// Extract header
	assert(length >= 1 + sizeof(uint32_t));
	uint32_t id;
	memcpy(&id, data, sizeof id);
	data += sizeof id;
	length -= sizeof id;
	char op = *data;
	data ++;
	length --;
	// Find the correct task to run
	struct task_desc *found = NULL;
	for (struct task_desc *desc = task_descs; desc->name; desc ++)
		if (desc->name == op) {
			found = desc;
			break;
		}
	if (!found) {
		// The task is unknown, report so
		uint8_t error[sizeof id + 1];
		memcpy(error, &id, sizeof id);
		memcpy(error + sizeof id, "U", 1);
		uplink_plugin_send_message(context, error, sizeof error);
	}
	assert(found->start);
	pid_t pid;
	int out;
	struct task_data *task_data = found->start(context, context->user_data->pool, data, length, &out, &pid);
	if (out) {
		// There'll be some output in future. Put the structure in there.
		// TODO: Put the task into the structures
	} else {
		// No output expected. Finish up now.
		bool ok;
		size_t result_size;
		uint8_t *result = found->finish(context, task_data, NULL, 0, &result_size, &ok);
		size_t message_size = sizeof id + 1 + result_size;
		uint8_t *message = mem_pool_alloc(context->temp_pool, message_size);
		memcpy(message, &id, sizeof id);
		message[sizeof id] = ok ? 'F' : 'O';
		memcpy(message + 1 + sizeof id, result, result_size);
		uplink_plugin_send_message(context, message, message_size);
		cleanup(context);
	}
}

#ifdef STATIC
struct plugin *plugin_info_sniff(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Sniff",
		.init_callback = initialize,
		.uplink_data_callback = in_request
	};
	return &plugin;
}

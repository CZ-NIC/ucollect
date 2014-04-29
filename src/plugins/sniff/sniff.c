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
#include "../../core/util.h"

#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>

#define GROW_RATIO 3
#define GROW_ADDITION 1024

// Single running task.
struct task {
	struct task *next, *prev; // Link list.
	struct task_desc *desc; // Description of the task
	struct task_data *data; // Data of the task
	uint32_t id; // ID, just bytes copied from the request
	pid_t pid; // PID of the child performing the request
	int out; // FD of its stdout
	uint8_t *buffer; // Buffer where we put the output to be parsed
	size_t buffer_used, buffer_allocated;
};

struct user_data {
	struct mem_pool *pool; // Pool for temporary data for tasks. Will be flushed whenever there's no task running.
	struct task *head, *tail; // Currently running tasks.
};

#define LIST_NODE struct task
#define LIST_BASE struct user_data
#define LIST_PREV prev
#define LIST_NAME(X) tasks_##X
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_REMOVE
#define LIST_WANT_LFOR
#include "../../core/link_list.h"

static void initialize(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.pool = loop_pool_create(context->loop, context, "Sniffer pool")
	};
}

static void cleanup(struct context *context) {
	// If no tasks are running, we can clean up the memory pool
	if (!context->user_data->head)
		mem_pool_reset(context->user_data->pool);
}

// Run the ->finish and send the answer to the server.
static void reply_send(struct context *context, uint32_t id, struct task_desc *desc, struct task_data *data, uint8_t *output, size_t output_size) {
	bool ok;
	size_t result_size;
	const uint8_t *result = desc->finish(context, data, output, output_size, &result_size, &ok);
	ulog(LLOG_INFO, "Finished task %s, success %d\n", desc->label, (int)ok);
	size_t message_size = sizeof id + 1 + result_size;
	uint8_t *message = mem_pool_alloc(context->temp_pool, message_size);
	memcpy(message, &id, sizeof id);
	message[sizeof id] = ok ? 'F': 'O';
	memcpy(message + 1 + sizeof id, result, result_size);
	uplink_plugin_send_message(context, message, message_size);
	cleanup(context);
}

static void data_received(struct context *context, int fd, struct task *task) {
	assert(task->out == fd);
	if (task->buffer_used == task->buffer_allocated) {
		// Not enough space to read to. Get some more (copy the existing, memory pools don't know realloc)
		task->buffer_allocated = task->buffer_allocated * GROW_RATIO + GROW_ADDITION;
		uint8_t *new = mem_pool_alloc(context->user_data->pool, task->buffer_allocated);
		memcpy(new, task->buffer, task->buffer_used);
		task->buffer = new;
	}
	// Read a bit of data
	ssize_t amount = read(fd, task->buffer + task->buffer_used, task->buffer_allocated - task->buffer_used);
	if (amount <= 0) { // There'll be no more data.
		if (amount < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ulog(LLOG_WARN, "Woken up to read from pipe %d, but nothing in there\n", fd);
				return;
			}
			ulog(LLOG_ERROR, "Error reading from task pipe %d: %s\n", fd, strerror(errno));
			// Reset the output to signal error
			task->buffer_used = 0;
			task->buffer = NULL;
		}
		tasks_remove(context->user_data, task); // Remove the task and its FD
		loop_plugin_unregister_fd(context, fd);
		if (close(fd) == -1)
			ulog(LLOG_ERROR, "Couldn't close task pipe %d: %s\n", fd, strerror(errno));
		reply_send(context, task->id, task->desc, task->data, task->buffer, task->buffer_used);
		// Due to the unregister, we won't be called again for this FD
	} else
		// We have not read everything yet. Wait for more.
		task->buffer_used += amount;
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
	// Abort any existing task with the same ID (the server might not know about it → it is of no use, or ask to terminate it with a NOP task)
	LFOR(tasks, old, context->user_data)
		if (old->id == id) {
			// Abort it. Kill the proces, close the output and remove it from the loop.
			if (kill(old->pid, SIGTERM) == -1) {
				if (errno == ESRCH) {
					ulog(LLOG_WARN, "Tried to terminate process %d of task %s, but it no longer existed\n", old->pid, old->desc->label);
				} else {
					ulog(LLOG_ERROR, "Couldn't kill process %d of task %s: %s\n", old->pid, old->desc->label, strerror(errno));
				}
			}
			loop_plugin_unregister_fd(context, old->out);
			if (close(old->out) == -1)
				ulog(LLOG_ERROR, "Couldn't close task's %s output FD %d: %s\n", old->desc->label, old->out, strerror(errno));
			// Remove the info about the task, it is no longer running.
			tasks_remove(context->user_data, old);
			// Release the memory if it was the last task there.
			cleanup(context);
			ulog(LLOG_INFO, "Task %s aborted, new task with the same ID arrived\n", old->desc->label);
			// Send info about the lost task to the server.
			uint8_t *message = mem_pool_alloc(context->temp_pool, sizeof id + 1);
			memcpy(message, &id, sizeof id);
			message[sizeof id] = 'A';
			uplink_plugin_send_message(context, message, sizeof id + 1);
			break;
		}
	assert(found->start);
	pid_t pid;
	int out;
	struct task_data *task_data = found->start(context, context->user_data->pool, data, length, &out, &pid);
	ulog(LLOG_INFO, "Started task %s as PID %d and fd %d\n", found->label, (int)pid, out);
	if (out) {
		if (fcntl(out, F_SETFL, O_NONBLOCK) == -1) {
			ulog(LLOG_ERROR, "Couldn't set output FD %d as non-blocking: %s\n", out, strerror(errno));
			if (close(out) == -1)
				ulog(LLOG_ERROR, "Error closing task output: %s\n", strerror(errno));
			reply_send(context, id, found, task_data, NULL, 0);
			return;
		}
		// There'll be some output in future. Put the structure in there.
		struct task *t = tasks_append_pool(context->user_data, context->user_data->pool); // Don't do the c99 initialization, it would overwrite next and prev pointers.
		t->desc = found;
		t->data = task_data;
		t->id = id;
		t->pid = pid;
		t->out = out;
		t->buffer_used = t->buffer_allocated = 0;
		t->buffer = NULL;
		loop_plugin_register_fd(context, out, t);
	} else {
		// No output expected. Finish up now.
		reply_send(context, id, found, task_data, NULL, 0);
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
		.uplink_data_callback = in_request,
		.fd_callback = (fd_callback_t) data_received
	};
	return &plugin;
}

/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "queue.h"

#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/loop.h"

#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#define QUEUE_FLUSH_TIME 5000

struct queue {
	bool active, timeout_started;
	int ipset_pipe;
	pid_t pid;
	size_t timeout_id;
};

struct queue *queue_alloc(struct context *context) {
	struct queue *result = mem_pool_alloc(context->permanent_pool, sizeof *result);
	*result = (struct queue) {
		.active = false
	};
	return result;
}

static void start(struct context *context, struct queue *queue) {
	assert(!queue->active);
	int pipes[2];
	sanity(pipe(pipes) != -1, "Couldn't create FWUp pipe: %s\n", strerror(errno));
	struct loop *loop = context->loop;
	/*
	 * Register the write end. This one will be in the parent process,
	 * therefore it needs to be watched and killed in case the plugin
	 * dies. It will also be auto-closed in the child by loop_fork(),
	 * saving us the bother to close it manually there.
	 */
	loop_plugin_register_fd(context, pipes[1], NULL);
	pid_t pid = loop_fork(loop);
	if (pid)
		// The parent doesn't need the read end, no matter if the fork worked or not.
		sanity(close(pipes[0]) != -1, "Couldn't close the read end of FWUp pipe: %s\n", strerror(errno));
	sanity(pid != -1, "Couldn't fork the ipset command: %s\n", strerror(errno));
	if (pid) {
		// The parent. Update the queue and be done with it.
		queue->active = true;
		queue->ipset_pipe = pipes[1];
		queue->pid = pid;
	} else {
		// The child. Screw the pipe into our input and exec to ipset command.
		if (dup2(pipes[0], 0) == -1)
			die("Couldn't attach the pipe to ipset input: %s\n", strerror(errno));
		// Get rid of the original.
		close(pipes[0]);
		execl("/usr/sbin/ipset", "ipset", "-exist", "restore", (char *)NULL);
		// Still here? The above must have failed :-(
		die("Couldn't exec ipset: %s\n", strerror(errno));
	}
}

static void lost(struct context *context, struct queue *queue, bool error) {
	assert(queue->active);
	if (error)
		ulog(LLOG_WARN, "Lost connection to ipset command %d, data may be out of sync\n", queue->pid);
	sanity(close(queue->ipset_pipe) == 0, "Error closing the ipset pipe: %s\n", strerror(errno));
	loop_plugin_unregister_fd(context, queue->ipset_pipe);
	queue->ipset_pipe = 0;
	queue->active = false;
	queue->pid = 0;
	if (queue->timeout_started) {
		queue->timeout_started = false;
		loop_timeout_cancel(context->loop, queue->timeout_id);
	}
}

static void flush_timeout(struct context *context, void *data, size_t id __attribute__((unused))) {
	struct queue *queue = data;
	queue->timeout_started = false;
	queue_flush(context, queue);
}

void enqueue(struct context *context, struct queue *queue, const char *command) {
	if (!queue->active)
		start(context, queue);
	assert(queue->active);
	assert(queue->ipset_pipe > 0);
	size_t len = strlen(command);
	assert(len);
	assert(command[len - 1] == '\n');
	while (len) {
		ssize_t sent = send(queue->ipset_pipe, command, len, MSG_NOSIGNAL);
		if (sent == -1) {
			switch (errno) {
				case ECONNRESET:
				case EPIPE:
					lost(context, queue, true);
					return;
				case EINTR:
					ulog(LLOG_WARN, "Interrupted while writing data to ipset, retrying\n");
					continue;
				default:
					sanity(false, "Error writing to ipset: %s\n", strerror(errno));
			}
		}
		// Move forward in whatever was sent
		command += sent;
		len -= sent;
	}
	if (!queue->timeout_started) {
		queue->timeout_started = true;
		queue->timeout_id = loop_timeout_add(context->loop, QUEUE_FLUSH_TIME, context, queue, flush_timeout);
	}
}

void queue_flush(struct context *context, struct queue *queue) {
	lost(context, queue, false);
}

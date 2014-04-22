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

#ifndef UCOLLECT_SNIFF_TASK_H
#define UCOLLECT_SNIFF_TASK_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

struct task_data;
struct context;
struct mem_pool;

/*
 * Description of task type.
 *
 * A server requests a task to be run, it is then started in background process.
 * The output is then sent from the subtask to its stdout and read. It is then
 * postprocessed and answer sent to server.
 */
struct task_desc {
	char name; // Single-character name of the task type, as sent over the protocol.
	char *label; // Human readable label of the type, for logs.
	/*
	 * Start the task.
	 *
	 * Context is the plugin's context.
	 * The pool is for data that can be needed during the time of the task, it is guaranteed to be valid until finish is called.
	 * Message is what arrived from the server, parameters of the task. Interpretation is up to the task type.
	 * The output is FD where the output will appear and pid is PID of the process.
	 *
	 * The return value is then passed to finish unmodified, it is meant as private task data.
	 *
	 * If you return 0 as out, it is considered the task failed to start. The finish is called right away to generate output.
	 */
	struct task_data *(*start)(struct context *context, struct mem_pool *pool, const uint8_t *message, size_t message_size, int *output, pid_t *pid);
	/*
	 * Postprocess the task. It is run after the output FD is closed.
	 *
	 * The context is context of the plugin.
	 * Data is what was returned from start.
	 * Output (and output size) is what got out of the output FD. NULL means there was an error ‒ either start signaled one or it wasn't possible to read the output. If there's no data output from out FD, but it is closed correctly, output_size is 0, but non-NULL pointer is passed.
	 * The result_size is size of the message to be sent to the server.
	 * OK is output parameter signalling if all went well.
	 *
	 * Return pointer to data to be sent to server (it may be allocated either from the memory pool passed to start or temporary pool in the context, either is fine).
	 */
	const uint8_t *(*finish)(struct context *context, struct task_data *data, const uint8_t *output, size_t output_size, size_t *result_size, bool *ok);
};

extern struct task_desc task_descs[];

#endif

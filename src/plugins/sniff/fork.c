/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "fork.h"

#include "../../core/util.h"
#include "../../core/loop.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

bool fork_task(struct loop *loop, const char *program, char **argv, const char *name, int *output, pid_t *pid) {
	int pipes[2];
	if (pipe(pipes) == -1) {
		ulog(LLOG_ERROR, "Couldn't create %s pipes: %s\n", name, strerror(errno));
		return false;
	}
	pid_t new_pid = loop_fork(loop);
	if (new_pid == -1) {
		ulog(LLOG_ERROR, "Couldn't create new %s process: %s\n", name, strerror(errno));
		if (close(pipes[0]) == -1)
			ulog(LLOG_ERROR, "Failed to close %s read pipe: %s\n", name, strerror(errno));
		if (close(pipes[1]) == -1)
			ulog(LLOG_ERROR, "Failed to close %s write pipe: %s\n", name, strerror(errno));
		return false;
	}
	if (new_pid == 0) { // We are the child now.
		sanity(close(pipes[0]) != -1, "Failed to close %s read pipe in child: %s\n", name, strerror(errno));
		sanity(dup2(pipes[1], 1) != -1, "Failed to assign stdout of %s: %s\n", name, strerror(errno));
		sanity(close(pipes[1]) != -1, "Failed to close copy of %s write pipe: %s\n", name, strerror(errno));
		execv(program, argv);
		sanity(false, "Failed to execute %s (%s): %s\n", name, program, strerror(errno));
	} else {
		if (close(pipes[1]) == -1)
			ulog(LLOG_ERROR, "Couldn't close %s write pipe: %s\n", name, strerror(errno));
		ulog(LLOG_DEBUG, "Task %s (%s) started with FD %d and PID %d\n", name, program, pipes[0], (int) new_pid);
		*output = pipes[0];
		*pid = new_pid;
	}
	return true;
}

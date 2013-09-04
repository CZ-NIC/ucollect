/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC

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

#include "../core/loop.h"
#include "../core/util.h"
#include "../core/plugin.h"
#include "../core/uplink.h"
#include "../core/configure.h"

#include <signal.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

// The loop is global, so we can use it from the signal handler.
static struct loop *loop;

// Handling of signals to terminate.
static void stop_signal_handler(int unused) {
	(void) unused;
	loop_break(loop);
}

static const int stop_signals[] = {
	SIGINT,
	SIGQUIT,
	SIGTERM
};

// Data used from the cleanup handler
static struct uplink *uplink;

static void cleanup(void) {
	if (uplink)
		uplink_destroy(uplink);
	loop_destroy(loop);
}

int main(int argc, const char* argv[]) {
	(void) argc;
	openlog("ucollect", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
	if (argv[1]) {
		ulog(LLOG_DEBUG, "Setting config dir to %s\n", argv[1]);
		config_set_dir(argv[1]);
	}
	// Create the loop.
	loop = loop_create();

	// Connect upstream
	uplink = uplink_create(loop);

	// Register all stop signals.
	for (size_t i = 0; i < sizeof stop_signals / sizeof *stop_signals; i ++) {
		struct sigaction action = {
			.sa_handler = stop_signal_handler,
			/*
			 * We want to disturb as little as possible (SA_RESTART).
			 * If the cleanup gets stuck and the user gets impatient and presses CTRL+C again,
			 * we want to terminate the hard wait instead of doing clean shutdown. So use
			 * the default handler for the second attempt (SA_RESETHAND).
			 */
			.sa_flags = SA_RESTART | SA_RESETHAND
		};
		if (sigaction(stop_signals[i], &action, NULL) != 0)
			die("Could not set signal handler for signal %d (%s)\n", stop_signals[i], strerror(errno));
	}

	if (!load_config(loop)) {
		ulog(LLOG_ERROR, "No configuration available\n");
		cleanup();
		return 1;
	}

	// Run until a stop signal comes.
	loop_run(loop);

	cleanup();
	return 0;
}

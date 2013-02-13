#include "../core/loop.h"
#include "../core/util.h"

#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

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
	SIGHUP,
	SIGTERM
};

int main(int argc, const char* argv[]) {
	(void) argc;
	(void) argv;

	// Create the loop.
	loop = loop_create();

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

	// TODO: Load all the plugins here.

	// Run until a stop signal comes.
	loop_run(loop);
	printf("Stopped\n");
	// TODO: Release all the plugins here.
	loop_destroy(loop);
	return 0;
}

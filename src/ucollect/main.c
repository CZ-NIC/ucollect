#include "../core/loop.h"
#include "../core/util.h"
#include "../core/plugin.h"

// FIXME: This is hardcoded for now, remove once we have a plugin loader
#include "../plugins/count/count.h"

#include <signal.h>
#include <string.h>
#include <errno.h>

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

static void cleanup() {
	// TODO: Release all the plugins here.
	loop_destroy(loop);
}

int main(int argc, const char* argv[]) {
	if (argc < 2)
		die("usage: %s <interface name> <local net address> <local net address> ...\n", argv[0]);

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

	// Provide the interface name
	if (!loop_add_pcap(loop, argv[1])) {
		cleanup();
		return 1;
	}

	// Provide the locat network ranges, so we can detect in and out packets
	for (int i = 2; i < argc; i ++)
		if (!loop_pcap_add_address(loop, argv[i])) {
			cleanup();
			return 1;
		}

	// TODO: Load all the plugins here.

	// FIXME: This is hardcoded just for now.
	loop_add_plugin(loop, plugin_info());

	// Run until a stop signal comes.
	loop_run(loop);

	cleanup();
	return 0;
}

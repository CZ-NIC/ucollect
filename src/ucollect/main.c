#include "../core/loop.h"
#include "../core/util.h"
#include "../core/plugin.h"
#include "../core/uplink.h"

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

// Data used from the cleanup handler
static struct uplink *uplink;
static struct loop_configurator *configurator;

static void cleanup() {
	// TODO: Release all the plugins here.
	if (uplink)
		uplink_destroy(uplink);
	if (configurator)
		loop_config_abort(configurator);
	loop_destroy(loop);
}

int main(int argc, const char* argv[]) {
	if (argc < 4)
		die("usage: %s <interface name> <server name> <server port> <local net address> <local net address> ...\n", argv[0]);

	// Create the loop.
	loop = loop_create();

	// Connect upstream
	uplink = uplink_create(loop, argv[2], argv[3]);

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

	configurator = loop_config_start(loop);

	// Provide the interface name
	if (!loop_add_pcap(configurator, argv[1])) {
		cleanup();
		return 1;
	}

	// Provide the locat network ranges, so we can detect in and out packets
	for (int i = 4; i < argc; i ++)
		if (!loop_pcap_add_address(configurator, argv[i])) {
			cleanup();
			return 1;
		}

	// FIXME: This is hardcoded just for now.
	if (!loop_add_plugin(configurator, "libplugin_count.so")) {
		cleanup();
		return 1;
	}

	loop_config_commit(configurator);
	configurator = NULL;

	// Run until a stop signal comes.
	loop_run(loop);

	cleanup();
	return 0;
}

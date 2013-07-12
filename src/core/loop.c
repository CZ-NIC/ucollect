#include "loop.h"
#include "mem_pool.h"
#include "util.h"
#include "context.h"
#include "plugin.h"
#include "packet.h"
#include "tunable.h"
#include "loader.h"
#include "configure.h"
#include "uplink.h"

#include <signal.h> // for sig_atomic_t
#include <assert.h>
#include <string.h> // Why is memcpy in string?
#include <errno.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <time.h>
#include <limits.h>
#include <setjmp.h>
#include <stdlib.h>

/*
 * Low-level error handling.
 *
 * If we are in a plugin, we have the context stored. We also have the
 * jump_ready variable. If it is set, it means the jump_env is ready to
 * jump to from signal handler.
 *
 * So we set the signal handlers and jump from them if a problem happens.
 * It depends on what is catching that, but usually the plugin will be
 * re-initialized if that happens.
 *
 * If the signal happens, the signal number is stored in jump_signum.
 *
 * This is, unfortunately, not reentrant :-(. Any idea how to make it so?
 */

static volatile sig_atomic_t jump_ready = 0;
static jmp_buf jump_env;
static volatile struct context *current_context = NULL;
static int jump_signum = 0;
static bool sig_initialized;

static void abort_safe(void) {
	// Disable catching the signal first.
	struct sigaction sa = {
		.sa_handler = SIG_DFL
	};
	sigaction(SIGABRT, &sa, NULL);
	abort();
	// Couldn't commit suicide yet? Try exit.
	exit(1);
	// Still nothing?
	kill(getpid(), SIGKILL);
}

static void sig_handler(int signal) {
	if (jump_ready && current_context) {
		jump_ready = 0; // Don't try to jump twice in a row if anything goes bad
		// There's a handler
		jump_signum = signal;
#ifdef DEBUG
		ulog(LOG_WARN, "Trying to create a core dump (if they are enabled)\n");
		/*
		 * Create a core dump. Do it by copying the process by fork and then
		 * aborting the child. Abort creates a core dump, if it is enabled.
		 */
		if (fork() == 0)
			abort_safe();
#endif
		longjmp(jump_env, 1);
	} else {
		// Not ready to jump. Abort.
		abort_safe();
	}
}

static const int signals[] = {
	SIGILL,
	SIGTRAP,
	SIGABRT,
	SIGBUS,
	SIGFPE,
	SIGSEGV,
	SIGPIPE,
	SIGALRM,
	SIGTTIN,
	SIGTTOU,
	SIGHUP
};

static void signal_initialize(void) {
	ulog(LOG_INFO, "Initializing emergency signal handlers\n");
	struct sigaction action = {
		.sa_handler = sig_handler,
		.sa_flags = SA_NODEFER
	};
	for (size_t i = 0; i < sizeof signals / sizeof signals[0]; i ++)
		if (sigaction(signals[i], &action, NULL) == -1)
			die("Sigaction failed for signal %d: %s\n", signals[i], strerror(errno));
}

#define PLUGIN_HOLDER_CANARY 0x7a92f998 // Just some random 4-byte number

struct pool_node {
	struct pool_node *next;
	struct mem_pool *pool;
};

struct pool_list {
	struct pool_node *head, *tail;
};

#define LIST_NODE struct pool_node
#define LIST_BASE struct pool_list
#define LIST_NAME(X) pool_##X
#define LIST_WANT_APPEND_POOL
#include "link_list.h"

static void pool_list_destroy(const struct pool_list *list) {
	for (struct pool_node *pool = list->head; pool; pool = pool->next)
		mem_pool_destroy(pool->pool);
}

#define PCAP_DIR_IN 0
#define PCAP_DIR_OUT 1

struct pcap_interface;

struct pcap_sub_interface {
	/*
	 * This will be always set to pcap_read_*. Trick to make the epollhandling
	 * simpler ‒ we put this struct directly as the user data to epoll and the
	 * generic handler calls the handler found, no matter what type it is.
	 *
	 * This item must be first in the data structure. It'll be then casted to
	 * the epoll_handler, which contains a function pointer as the first element.
	 */
	void (*handler)(struct pcap_sub_interface *sub, uint32_t events);
	pcap_t *pcap;
	int fd;
	struct pcap_interface *interface;
};

struct pcap_interface {
	// Link back to the loop owning this pcap. For epoll handler.
	struct loop *loop;
	const char *name;
	struct pcap_sub_interface directions[2];
	size_t offset;
	int datalink;
	size_t watchdog_timer;
	bool watchdog_received,  watchdog_initialized;
	size_t watchdog_missed;
	struct pcap_interface *next;
	bool mark; // Mark for configurator.
	bool in; // Currently processed direction is in (temporary internal mark)
	// Statistics from the last time, so we can return just the diffs
	size_t captured, dropped, if_dropped;
};

struct pcap_list {
	struct pcap_interface *head, *tail;
	size_t count;
};

#define LIST_NODE struct pcap_interface
#define LIST_BASE struct pcap_list
#define LIST_NAME(X) pcap_##X
#define LIST_COUNT count
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#include "link_list.h"

struct plugin_holder {
	/*
	 * This one is first, so we can cast the current_context back in case
	 * of error handling or some other callback.
	 */
	struct context context;
#ifdef DEBUG
	uint32_t canary; // To be able to check it is really a plugin holder
#endif
	const char *libname;
	void *plugin_handle;
	struct plugin plugin;
	struct pool_list pool_list;
	struct plugin_holder *next;
	struct plugin_holder *original; // When copying, in the configurator
	bool mark; // Mark for configurator.
	size_t failed;
};

struct plugin_list {
	struct plugin_holder *head, *tail;
};

#define LIST_NODE struct plugin_holder
#define LIST_BASE struct plugin_list
#define LIST_NAME(X) plugin_##X
#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#include "link_list.h"

/*
 * Generate a wrapper around a plugin callback that:
 *  * Checks it the callback is not NULL (if it is, nothing is called)
 *  * Sets the current context to the one of the plugin (for error handling)
 *  * Calls the callback
 *  * Restores no context and resets the temporary pool
 */
#define GEN_CALL_WRAPPER(NAME) \
static void plugin_##NAME(struct plugin_holder *plugin) { \
	if (!plugin->plugin.NAME##_callback) \
		return; \
	current_context = &plugin->context; \
	plugin->plugin.NAME##_callback(&plugin->context); \
	mem_pool_reset(plugin->context.temp_pool); \
	current_context = NULL; \
}

// The same, with parameter
#define GEN_CALL_WRAPPER_PARAM(NAME, TYPE) \
static void plugin_##NAME(struct plugin_holder *plugin, TYPE PARAM) { \
	if (!plugin->plugin.NAME##_callback) \
		return; \
	current_context = &plugin->context; \
	plugin->plugin.NAME##_callback(&plugin->context, PARAM); \
	mem_pool_reset(plugin->context.temp_pool); \
	current_context = NULL; \
}

// And with 2
#define GEN_CALL_WRAPPER_PARAM_2(NAME, TYPE1, TYPE2) \
static void plugin_##NAME(struct plugin_holder *plugin, TYPE1 PARAM1, TYPE2 PARAM2) { \
	if (!plugin->plugin.NAME##_callback) \
		return; \
	current_context = &plugin->context; \
	plugin->plugin.NAME##_callback(&plugin->context, PARAM1, PARAM2); \
	mem_pool_reset(plugin->context.temp_pool); \
	current_context = NULL; \
}

GEN_CALL_WRAPPER(init)
GEN_CALL_WRAPPER(finish)
GEN_CALL_WRAPPER(uplink_connected)
GEN_CALL_WRAPPER(uplink_disconnected)
GEN_CALL_WRAPPER_PARAM(packet, const struct packet_info *)
GEN_CALL_WRAPPER_PARAM_2(uplink_data, const uint8_t *, size_t)

struct timeout {
	uint64_t when;
	void (*callback)(struct context *context, void *data, size_t id);
	struct context *context;
	void *data;
	size_t id;
};

struct loop {
	/*
	 * The pools used for allocating memory.
	 *
	 * The permanent_pool is not reset/released for the whole lifetime of the loop.
	 *
	 * The batch_pool is reset after each loop iteration (which may be several handled
	 * events). You may not assume it'll stay valid between different events.
	 *
	 * The temp_pool is reset after each callback is finished, serving as a scratchpad
	 * for the callbacks.
	 */
	struct mem_pool *permanent_pool, *config_pool, *batch_pool, *temp_pool;
	struct pool_list pool_list;
	// The PCAP interfaces to capture on.
	struct pcap_list pcap_interfaces;
	// The plugins that handle the packets
	struct plugin_list plugins;
	struct uplink *uplink;
	// Timeouts. Sorted by the 'when' element.
	struct timeout *timeouts;
	size_t timeout_count, timeout_capacity;
	// Last time the epoll returned, in milliseconds since some unspecified point in history
	uint64_t now;
	// The epoll
	int epoll_fd;
	// Turnes to 1 when we are stopped.
	volatile sig_atomic_t stopped; // We may be stopped from a signal, so not bool
	volatile sig_atomic_t reconfigure; // Set to 1 when there's SIGHUP and we should reconfigure
	volatile sig_atomic_t reconfigure_full; // De-initialize first.
	struct context *reinitialize_plugin; // Please reinitialize this plugin on return from jump
	bool retry_reconfigure_on_failure;
};

// Some stuff for yet uncommited configuration
struct loop_configurator {
	struct loop *loop;
	struct mem_pool *config_pool;
	struct pcap_list pcap_interfaces;
	struct plugin_list plugins;
	const char *remote_name, *remote_service, *login, *password;
};

// Handle one packet.
static void packet_handler(struct pcap_interface *interface, const struct pcap_pkthdr *header, const unsigned char *data) {
	struct packet_info info = {
		.length = header->caplen,
		.data = data,
		.interface = interface->name,
		.direction = interface->in ? DIR_IN : DIR_OUT
	};
	ulog(LOG_DEBUG_VERBOSE, "Packet of size %zu on interface %s (starting %016llX%016llX, on layer %d)\n", info.length, interface->name, *(long long unsigned *) info.data, *(1 + (long long unsigned *) info.data), interface->datalink);
	parse_packet(&info, interface->loop->batch_pool, interface->datalink);
	LFOR(plugin, plugin, &interface->loop->plugins)
		plugin_packet(plugin, &info);
}

static void self_reconfigure(struct context *context, void *data, size_t id) {
	(void) context;
	(void) data;
	(void) id;
	/*
	 * The easiest way to reconfigure ourselves is to send self the SIGHUP signal.
	 * We can't really reconfigure here, as it would break the loop. And setting
	 * the reconfigure flag might have effect after long time.
	 */
	if (kill(getpid(), SIGHUP) == -1)
		die("Couldn't SIGHUP self (%s)\n", strerror(errno));
}

static void pcap_read(struct pcap_sub_interface *sub, uint32_t unused) {
	(void) unused;
	ulog(LOG_DEBUG_VERBOSE, "Read on interface %s\n", sub->interface->name);
	sub->interface->in = sub == &sub->interface->directions[0];
	int result = pcap_dispatch(sub->pcap, MAX_PACKETS, (pcap_handler) packet_handler, (unsigned char *) sub->interface);
	if (result == -1) {
		ulog(LOG_ERROR, "Error reading packets from PCAP on %s (%s)\n", sub->interface->name, pcap_geterr(sub->pcap));
		sub->interface->loop->retry_reconfigure_on_failure = true;
		self_reconfigure(NULL, NULL, 0); // Try to reconfigure on the next loop iteration
	}
	sub->interface->watchdog_received = true;
	ulog(LOG_DEBUG_VERBOSE, "Handled %d packets on %s/%p\n", result, sub->interface->name, (void *) sub);
}

static void epoll_register_pcap(struct loop *loop, struct pcap_interface *interface, int op) {
	for (size_t i = 0; i < 2; i ++) {
		struct epoll_event event = {
			.events = EPOLLIN,
			.data = {
				.ptr = &interface->directions[i]
			}
		};
		if (epoll_ctl(loop->epoll_fd, op, interface->directions[i].fd, &event) == -1)
			die("Can't register PCAP fd %d of %s to epoll fd %d (%s)\n", interface->directions[i].fd, interface->name, loop->epoll_fd, strerror(errno));
	}
}

static void loop_get_now(struct loop *loop) {
	struct timespec ts;
	/*
	 * CLOC_MONOTONIC can go backward or jump if admin adjusts date.
	 * But the CLOCK_MONOTONIC_RAW doesn't seem to be available in uclibc.
	 * Any better alternative?
	 */
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		die("Couldn't get time (%s)\n", strerror(errno));
	loop->now = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

struct loop *loop_create(void) {
#ifndef NO_SIGNAL_RESCUE
	if (!sig_initialized) {
		signal_initialize();
		sig_initialized = true;
	}
#endif
	ulog(LOG_INFO, "Creating a main loop\n");
	/*
	 * 42 is arbitrary choice. The man page says it is ignored except it must
	 * be positive number.
	 */
	int epoll_fd = epoll_create(42);
	if (epoll_fd == -1)
		die("Couldn't create epoll instance (%s)\n", strerror(errno));
	struct mem_pool *pool = mem_pool_create("Global permanent pool");
	struct loop *result = mem_pool_alloc(pool, sizeof *result);
	*result = (struct loop) {
		.permanent_pool = pool,
		.epoll_fd = epoll_fd
	};
	result->batch_pool = loop_pool_create(result, NULL, "Global batch pool");
	result->temp_pool = loop_pool_create(result, NULL, "Global temporary pool");
	loop_get_now(result);
	return result;
}

void loop_break(struct loop *loop) {
	loop->stopped = 1;
}

static void plugin_destroy(struct plugin_holder *plugin, bool emergency) {
	ulog(LOG_INFO, "Removing plugin %s\n", plugin->plugin.name);
	if (setjmp(jump_env)) {
		ulog(LOG_ERROR, "Signal %d during plugin finish, doing emergency shutdown instead\n", jump_signum);
		emergency = true;
	}
	jump_ready = true;
	if (!emergency)
		plugin_finish(plugin);
	size_t pos = 0;
	struct loop *loop = plugin->context.loop;
	while (pos < loop->timeout_count) {
		if (loop->timeouts[pos].context == &plugin->context) {
			// Drop this timeout, as we kill the corresponding plugin
			memmove(loop->timeouts + pos, loop->timeouts + pos + 1, (loop->timeout_count - pos - 1) * sizeof *loop->timeouts);
			loop->timeout_count --;
		} else
			pos ++;
	}
	jump_ready = false;
	pool_list_destroy(&plugin->pool_list);
	mem_pool_destroy(plugin->context.permanent_pool);
	plugin_unload(plugin->plugin_handle);
}

static int blocked_signals[] = {
	// Termination signals
	SIGINT,
	SIGQUIT,
	SIGTERM,
	// Reconfiguration
	SIGHUP,
	SIGUSR1
};

// Not thread safe, not even reentrant :-(
static volatile struct loop *current_loop;

static void request_reconfigure(int unused) {
	(void) unused;
	assert(current_loop);
	current_loop->reconfigure = 1;
}

static void request_reconfigure_full(int unused) {
	(void) unused;
	assert(current_loop);
	current_loop->reconfigure = 1;
	current_loop->reconfigure_full = 1;
}

void loop_run(struct loop *loop) {
	ulog(LOG_INFO, "Running the main loop\n");
	sigset_t blocked;
	// Block signals during actions, and let them only during the epoll
	sigemptyset(&blocked);
	for (size_t i = 0; i < sizeof blocked_signals / sizeof blocked_signals[0]; i ++)
		sigaddset(&blocked, blocked_signals[i]);
	sigset_t original_mask;
	if (sigprocmask(SIG_BLOCK, &blocked, &original_mask) == -1)
		die("Could not mask signals (%s)\n", strerror(errno));
	current_loop = loop;
	struct sigaction original_sighup, original_sigusr1;
	if (sigaction(SIGHUP, &(struct sigaction) { .sa_handler = request_reconfigure }, &original_sighup) == -1)
		die("Could not sigaction SIGHUP (%s\n)", strerror(errno));
	if (sigaction(SIGUSR1, &(struct sigaction) { .sa_handler = request_reconfigure_full }, &original_sigusr1) == -1)
		die("Could not sigaction SIGUSR1 (%s\n)", strerror(errno));
	REINIT:
	if (setjmp(jump_env)) {
		volatile struct context *context;
		bool failure = false;
		if (loop->reinitialize_plugin) {
			context = loop->reinitialize_plugin;
			loop->reinitialize_plugin = NULL;
		} else {
			failure = true;
			context = current_context;
		}
		if (context) {
			struct plugin_holder *holder = (struct plugin_holder *) context;
#ifdef DEBUG
			assert(holder->canary == PLUGIN_HOLDER_CANARY);
#endif
			bool reinit = true;
			size_t failed = 0;
			if (failure) {
				reinit = holder->failed < FAIL_COUNT;
				failed = holder->failed;
				ulog(LOG_ERROR, "Signal %d in plugin %s (failed %zu times before)\n", jump_signum, holder->plugin.name, failed);
			}
			plugin_destroy(holder, true);
			struct loop_configurator *configurator = loop_config_start(loop);
			holder->mark = false; // This one is already destroyed
			const char *libname = holder->libname; // Make sure it is not picked up
			holder->libname = "";
			LFOR(plugin, plugin, &loop->plugins)
				if (plugin->mark) { // Copy all the other plugins, and this one if it is to be reinited
					if (!loop_add_plugin(configurator, plugin->libname))
						die("Copy of %s failed\n", plugin->libname);
				} else if (reinit) {
					if (!loop_add_plugin(configurator, libname))
						ulog(LOG_ERROR, "Reinit of %s failed, aborting plugin\n", libname);
					else
						configurator->plugins.tail->failed = failed + 1;
				}
			LFOR(pcap, interface, &loop->pcap_interfaces) {
				if (!loop_add_pcap(configurator, interface->name))
					die("Copy of %s failed\n", interface->name);
			}
			loop_config_commit(configurator);
			goto REINIT;
		} else {
			ulog(LOG_ERROR, "Signal %d outside of plugin, aborting\n", jump_signum);
			abort();
		}
	}
	jump_ready = 1;
	loop_get_now(loop);
	while (!loop->stopped) {
		struct epoll_event events[MAX_EVENTS];
		int wait_time;
		if (loop->timeout_count) {
			// Set the wait time until the next timeout
			// Use larger type so we can check the bounds.
			int64_t wait = loop->timeouts[0].when - loop->now;
			if (wait < 0)
				wait = 0;
			if (wait > INT_MAX)
				wait = INT_MAX;
			wait_time = wait;
		} else {
			wait_time = -1; // Forever, if no timeouts
		}
		int ready = epoll_pwait(loop->epoll_fd, events, MAX_EVENTS, wait_time, &original_mask);
		loop_get_now(loop);
		if (loop->reconfigure) { // We are asked to reconfigure
			jump_ready = 0;
			loop->reconfigure = false;
			ulog(LOG_INFO, "Reconfiguring\n");
			if (loop->reconfigure_full)
				// Wipe out current configuration, so we start clean
				loop_config_commit(loop_config_start(loop));
			if (load_config(loop))
				loop->retry_reconfigure_on_failure = false;
			else {
				ulog(LOG_ERROR, "Reconfiguration failed, using previous configuration\n");
				if (loop->retry_reconfigure_on_failure)
					loop_timeout_add(loop, IFACE_RECONFIGURE_TIME, NULL, NULL, self_reconfigure);
			}
			goto REINIT;
		}
		// Handle timeouts.
		bool timeouts_called = false;
		while (loop->timeout_count && loop->timeouts[0].when <= loop->now) {
			// Take it out before calling. The callback might manipulate timeouts.
			struct timeout timeout = loop->timeouts[0];
			// Suboptimal, but there should be only few timeouts and not often
			memmove(loop->timeouts, loop->timeouts + 1, (-- loop->timeout_count) * sizeof *loop->timeouts);
			current_context = timeout.context;
			ulog(LOG_DEBUG, "Firing timeout %zu at %llu when %zu more timeouts active\n", timeout.id, (long long unsigned) timeout.when, loop->timeout_count);
			timeout.callback(timeout.context, timeout.data, timeout.id);
			mem_pool_reset(loop->temp_pool);
			current_context = NULL;
			timeouts_called = true;
		}
		// Handle events from epoll
		if (ready == -1) {
			if (errno == EINTR) {
				ulog(LOG_WARN, "epoll_wait on %d interrupted, retry\n", loop->epoll_fd);
				continue;
			}
			die("epoll_wait on %d failed: %s\n", loop->epoll_fd, strerror(errno));
		} else if (!ready && !timeouts_called) {
			// This is strange. We wait for 1 event idefinitelly and get 0
			ulog(LOG_WARN, "epoll_wait on %d returned 0 events and 0 timeouts\n", loop->epoll_fd);
		} else {
			for (size_t i = 0; i < (size_t) ready; i ++) {
				/*
				 * We have the event. Now, the data has the pointer to the handler
				 * as the first element. Therefore, we can cast it to the handler.
				 */
				struct epoll_handler *handler = events[i].data.ptr;
				handler->handler(events[i].data.ptr, events[i].events);
			}
		}
		mem_pool_reset(loop->batch_pool);
	}
	jump_ready = 0;
	if (sigaction(SIGUSR1, &original_sighup, NULL) == -1)
		die("Could not return sigaction of SIGUSR1 (%s)\n", strerror(errno));
	if (sigaction(SIGHUP, &original_sighup, NULL) == -1)
		die("Could not return sigaction of SIGHUP (%s)\n", strerror(errno));
	current_loop = NULL;
	if (sigprocmask(SIG_SETMASK, &blocked, &original_mask) == -1)
		die("Could not restore sigprocmask (%s)\n", strerror(errno));
}

static void pcap_destroy(struct pcap_interface *interface) {
	ulog(LOG_INFO, "Closing PCAP on %s\n", interface->name);
	if (interface->watchdog_initialized)
		loop_timeout_cancel(interface->loop, interface->watchdog_timer);
	for (size_t i = 0; i < 2; i ++)
		pcap_close(interface->directions[i].pcap);
}

void loop_destroy(struct loop *loop) {
	ulog(LOG_INFO, "Releasing the main loop\n");
	// Close the epoll
	int result = close(loop->epoll_fd);
	assert(result == 0);
	// Close all PCAPs
	for (struct pcap_interface *interface = loop->pcap_interfaces.head; interface; interface = interface->next)
		pcap_destroy(interface);
	// Remove all the plugins.
	for (struct plugin_holder *plugin = loop->plugins.head; plugin; plugin = plugin->next)
		plugin_destroy(plugin, false);
	pool_list_destroy(&loop->pool_list);
	// This mempool must be destroyed last, as the loop is allocated from it
	mem_pool_destroy(loop->permanent_pool);
}

// Open one direction of the capture.
static int pcap_create_dir(pcap_t **pcap, pcap_direction_t direction, const char *interface, const char *dir_txt) {
	ulog(LOG_INFO, "Initializing PCAP (%s) on %s\n", dir_txt, interface);
	// Open the pcap
	char errbuf[PCAP_ERRBUF_SIZE];
	*pcap = pcap_create(interface, errbuf);
	if (!*pcap) {
		ulog(LOG_ERROR, "Can't initialize PCAP (%s) on %s (%s)\n", dir_txt, interface, errbuf);
		return -1;
	}
	// Set parameters.
	int result = pcap_set_promisc(*pcap, 1);
	assert(result == 0); // Can error only on code errors
	result = pcap_set_timeout(*pcap, PCAP_TIMEOUT); // One second
	assert(result == 0);
	pcap_set_buffer_size(*pcap, PCAP_BUFFER);
	assert(result == 0);

	// TODO: Some filters?

	// Activate it
	result = pcap_activate(*pcap);
	switch (result) {
		// We need to manually distinguish what are errors, what warnings, etc.
		case 0: // All OK
			break;
		case PCAP_WARNING_PROMISC_NOTSUP:
		case PCAP_WARNING:
			// These are just warnings. Display them, but continue.
			ulog(LOG_WARN, "PCAP (%s) on %s: %s\n", dir_txt, interface, pcap_geterr(*pcap));
			break;
		default:
			/*
			 * Everything is an error. Even if it wasn't an error, we don't
			 * know it explicitly, so consider it error.
			 */
			ulog(LOG_ERROR, "PCAP on (%s) %s: %s, closing\n", dir_txt, interface, pcap_geterr(*pcap));
			pcap_close(*pcap);
			return -1;
	}
	// Set it non-blocking. We'll keep switching between pcaps of interfaces and other events.
	if (pcap_setnonblock(*pcap, 1, errbuf) == -1) {
		ulog(LOG_ERROR, "Can't set PCAP (%s) on %s non-blocking (%s)\n", dir_txt, interface, errbuf);
		pcap_close(*pcap);
		return -1;
	}
	// For some reason, this doesn't work before activated. Maybe it's just filter on the output?
	result = pcap_setdirection(*pcap, direction);
	assert(result == 0);

	// Get the file descriptor for the epoll.
	int fd = pcap_get_selectable_fd(*pcap);
	if (fd == -1) {
		ulog(LOG_ERROR, "Can't get FD for PCAP (%s) on %s\n", dir_txt, interface);
		pcap_close(*pcap);
		return -1;
	}
	assert(pcap_datalink(*pcap) <= DLT_PFLOG);
	return fd;
}

bool loop_add_pcap(struct loop_configurator *configurator, const char *interface) {
	// First, go through the old ones and copy it if is there.
	LFOR(pcap, old, &configurator->loop->pcap_interfaces)
		if (strcmp(interface, old->name) == 0) {
			old->mark = false; // We copy it, don't close it at commit
			struct pcap_interface *new = pcap_append_pool(&configurator->pcap_interfaces, configurator->config_pool);
			*new = *old;
			new->next = NULL;
			new->name = mem_pool_strdup(configurator->config_pool, interface);
			return true;
		}
	pcap_t *pcap_in;
	int fd_in = pcap_create_dir(&pcap_in, PCAP_D_IN, interface, "in");
	if (fd_in == -1)
		return false; // Error already reported

	pcap_t *pcap_out;
	int fd_out = pcap_create_dir(&pcap_out, PCAP_D_OUT, interface, "out");
	if (fd_out == -1) {
		pcap_close(pcap_in);
		return false;
	}

	// Put the PCAP into the new configuration loop.
	struct pcap_interface *new = pcap_append_pool(&configurator->pcap_interfaces, configurator->config_pool);
	*new = (struct pcap_interface) {
		.loop = configurator->loop,
		.name = mem_pool_strdup(configurator->config_pool, interface),
		.directions = {
			[PCAP_DIR_IN] = {
				.handler = pcap_read,
				.pcap = pcap_in,
				.fd = fd_in,
				.interface = new
			},
			[PCAP_DIR_OUT] = {
				.handler = pcap_read,
				.pcap = pcap_out,
				.fd = fd_out,
				.interface = new
			}
		},
		.datalink = pcap_datalink(pcap_in),
		.mark = true
	};
	return true;
}

size_t *loop_pcap_stats(struct context *context) {
	struct loop *loop = context->loop;
	size_t *result = mem_pool_alloc(context->temp_pool, (1 + 3 * loop->pcap_interfaces.count) * sizeof *result);
	*result = loop->pcap_interfaces.count;
	size_t pos = 1;
	LFOR(pcap, interface, &loop->pcap_interfaces) {
		memset(result + pos, 0, 3 * sizeof *result);
		for (size_t i = 0; i < 2; i ++) {
			struct pcap_stat ps;
			int error = pcap_stats(interface->directions[i].pcap, &ps);
			if (error) {
				memset(result + pos, 0xff, 3 * sizeof *result);
				break;
			} else {
				result[pos ++] += ps.ps_recv;
				result[pos ++] += ps.ps_drop;
				result[pos ++] += ps.ps_ifdrop - interface->if_dropped;
				interface->if_dropped = ps.ps_ifdrop;
			}
			pos -= 3;
		}

		size_t tmp = result[pos];
		result[pos ++] -= interface->captured;
		interface->captured = tmp;

		tmp = result[pos];
		result[pos ++] -= interface->dropped;
		interface->dropped = tmp;

		tmp = result[pos];
		result[pos ++] -= interface->if_dropped;
		interface->if_dropped = tmp;
	}
	return result;
}

bool loop_add_plugin(struct loop_configurator *configurator, const char *libname) {
	// Look for existing plugin first
	LFOR(plugin, old, &configurator->loop->plugins)
		if (strcmp(old->libname, libname) == 0) {
			old->mark = false; // We copy it, so don't delete after commit
			struct plugin_holder *new = plugin_append_pool(&configurator->plugins, configurator->config_pool);
			*new = *old;
			new->next = NULL;
			new->original = old;
			new->plugin.name = mem_pool_strdup(configurator->config_pool, old->plugin.name);
			new->libname = mem_pool_strdup(configurator->config_pool, libname);
			return true;
		}
	// Load the plugin
	struct plugin plugin;
	void *plugin_handle = plugin_load(libname, &plugin);
	if (!plugin_handle)
		return false;
	ulog(LOG_INFO, "Installing plugin %s\n", plugin.name);
	struct mem_pool *permanent_pool = mem_pool_create(plugin.name);
	assert(!jump_ready);
	if (setjmp(jump_env)) {
		ulog(LOG_ERROR, "Signal %d during plugin initialization, aborting load\n", jump_signum);
		mem_pool_destroy(permanent_pool);
		plugin_unload(plugin_handle);
		return false;
	}
	jump_ready = 1;
	/*
	 * Each plugin gets its own permanent pool (since we'd delete that one with the plugin),
	 * but we can reuse the temporary pool.
	 */
	struct plugin_holder *new = mem_pool_alloc(configurator->config_pool, sizeof *new);
	*new = (struct plugin_holder) {
		.context = {
			.temp_pool = configurator->loop->temp_pool,
			.permanent_pool = permanent_pool,
			.loop = configurator->loop,
			.uplink = configurator->loop->uplink
		},
		.libname = mem_pool_strdup(configurator->config_pool, libname),
		.plugin_handle = plugin_handle,
#ifdef DEBUG
		.canary = PLUGIN_HOLDER_CANARY,
#endif
		.plugin = plugin,
		.mark = true
	};
	// Copy the name (it may be temporary), from the plugin's own pool
	new->plugin.name = mem_pool_strdup(configurator->config_pool, plugin.name);
	plugin_init(new);
	jump_ready = 0;
	// Store the plugin structure.
	plugin_insert_after(&configurator->plugins, new, configurator->plugins.tail);
	return true;
}

void loop_uplink_set(struct loop *loop, struct uplink *uplink) {
	assert(!loop->uplink);
	loop->uplink = uplink;
	LFOR(plugin, plugin, &loop->plugins)
		plugin->context.uplink = uplink;
}

void loop_register_fd(struct loop *loop, int fd, struct epoll_handler *handler) {
	struct epoll_event event = {
		.events = EPOLLIN | EPOLLRDHUP,
		.data = {
			.ptr = handler
		}
	};
	if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
		die("Can't register fd %d to epoll fd %d (%s)\n", fd, loop->epoll_fd, strerror(errno));
}

struct mem_pool *loop_pool_create(struct loop *loop, struct context *context, const char *name) {
	struct pool_list *list = &loop->pool_list;
	struct mem_pool *pool = loop->permanent_pool;
	if (context) {
		struct plugin_holder *holder = (struct plugin_holder *) context;
#ifdef DEBUG
		assert(holder->canary == PLUGIN_HOLDER_CANARY);
#endif
		list = &holder->pool_list;
		pool = context->permanent_pool;
	}
	struct mem_pool *new = mem_pool_create(name);
	pool_append_pool(list, pool)->pool = new;
	return new;
}

struct mem_pool *loop_permanent_pool(struct loop *loop) {
	return loop->permanent_pool;
}

struct mem_pool *loop_temp_pool(struct loop *loop) {
	return loop->temp_pool;
}

bool loop_plugin_send_data(struct loop *loop, const char *name, const uint8_t *data, size_t length) {
	LFOR(plugin, plugin, &loop->plugins)
		if (strcmp(plugin->plugin.name, name) == 0) {
			plugin_uplink_data(plugin, data, length);
			return true;
		}
	return false;
}

const char *loop_plugin_get_name(const struct context *context) {
	const struct plugin_holder *holder = (struct plugin_holder *) context;
#ifdef DEBUG
	assert(holder->canary == PLUGIN_HOLDER_CANARY);
#endif
	return holder->plugin.name;
}

size_t loop_timeout_add(struct loop *loop, uint32_t after, struct context *context, void *data, void (*callback)(struct context *context, void *data, size_t id)) {
	if (after == 0)
		/*
		 * Schedule it for the next loop iteration. Prevents uninteruptible
		 * busy loop, as we accept signals only when waiting for events.
		 */
		after = 1;
	// Enough space?
	if (loop->timeout_count == loop->timeout_capacity) {
		loop->timeout_capacity = loop->timeout_capacity * 2;
		if (!loop->timeout_capacity)
			loop->timeout_capacity = 2; // Some basic size for the start
		struct timeout *new = mem_pool_alloc(loop->permanent_pool, loop->timeout_capacity * sizeof *new);
		memcpy(new, loop->timeouts, loop->timeout_count * sizeof *new);
		loop->timeouts = new;
		/* Yes, throwing out the old array. But with the double-growth, only linear
		 * amount of memory is wasted. And we reuse the space after timed-out timeouts,
		 * so it should not grow indefinitely.
		 */
	}
	uint64_t when = loop->now + after;
	// Sort it in, according to the value of when.
	size_t pos = 0;
	for (size_t i = loop->timeout_count; i; i --) {
		if (loop->timeouts[i - 1].when > when)
			loop->timeouts[i] = loop->timeouts[i - 1];
		else {
			pos = i;
			break;
		}
	}
	/*
	 * We let the id wrap around. We expect the old one with the same value already
	 * timet out a long time ago.
	 */
	static size_t id = 0;
	loop->timeouts[pos] = (struct timeout) {
		.when = when,
		.callback = callback,
		.context = context,
		.data = data,
		.id = id ++
	};
	ulog(LOG_DEBUG, "Adding timeout for %lu seconds, expected to fire at %llu, now %llu as ID %zu\n", (unsigned long) after,  (unsigned long long) when, (unsigned long long) loop->now, loop->timeouts[pos].id);
	assert(loop->now < when);
	loop->timeout_count ++;
	return loop->timeouts[pos].id;
}

void loop_timeout_cancel(struct loop *loop, size_t id) {
	for (size_t i = 0; i < loop->timeout_count; i ++)
		if (loop->timeouts[i].id == id) {
			// Move the rest one position left
			memmove(loop->timeouts + i, loop->timeouts + i + 1, (loop->timeout_count - 1 - i) * sizeof *loop->timeouts);
			loop->timeout_count --;
			return;
		}
	assert(0); // The ID is not there! Already called the timeout?
}

struct loop_configurator *loop_config_start(struct loop *loop) {
	// Create the configurator
	struct mem_pool *config_pool = mem_pool_create("Config pool");
	struct loop_configurator *result = mem_pool_alloc(config_pool, sizeof *result);
	*result = (struct loop_configurator) {
		.loop = loop,
		.config_pool = config_pool
	};
	// Mark all the old plugins and interfaces for deletion on commit
	LFOR(plugin, plugin, &loop->plugins)
		plugin->mark = true;
	LFOR(pcap, interface, &loop->pcap_interfaces)
		interface->mark = true;
	return result;
}

void loop_config_abort(struct loop_configurator *configurator) {
	/*
	 * Destroy all the newly-created plugins and interfaces (marked)
	 *
	 * Select the ones from the configurator, not loop!
	 */
	LFOR(plugin, plugin, &configurator->plugins)
		if (plugin->mark)
			plugin_destroy(plugin, false);
	LFOR(pcap, interface, &configurator->pcap_interfaces)
		if (interface->mark)
			pcap_destroy(interface);
	// And delete all the memory
	mem_pool_destroy(configurator->config_pool);
}

/*
 * In the rare situation when someone shuts down an interface and then removes it
 * (for example by unloading the module), we get a stray handle to non-existant
 * pcap. We do reinitialize when it is shut down, but then it stays inactive and
 * we get no error on the removal of the interface. This watchdog looks to see
 * if there are any data. If there are not any data for a long time, we try to
 * do a full reconfiguration, which would force us to open the interface again.
 * If it so happens the interface was really removed, we get an error now.
 */
static void pcap_watchdog(struct context *context_unused, void *data, size_t id_unused) {
	(void) context_unused;
	(void) id_unused;
	struct pcap_interface *interface = data;
	if (interface->watchdog_received) {
		interface->watchdog_missed = 0;
	} else {
		ulog(LOG_WARN, "No data on interface %s in a long time\n", interface->name);
		if (interface->watchdog_missed >= WATCHDOG_MISSED_COUNT) {
			ulog(LOG_ERROR, "Too many missed intervals of data on %s, doing full reconfigure in attempt to recover from unknown external errors\n", interface->name);
			interface->loop->retry_reconfigure_on_failure = true;
			if (kill(getpid(), SIGUSR1))
				die("Can't send SIGUSR1 to self (%s)\n", strerror(errno));
		}
		interface->watchdog_missed ++;
	}
	interface->watchdog_received = false;
	// Schedule new timeout after a long while, to see if we miss the next interval
	interface->watchdog_timer = loop_timeout_add(interface->loop, PCAP_WATCHDOG_TIME, NULL, interface, pcap_watchdog);
}

void loop_config_commit(struct loop_configurator *configurator) {
	struct loop *loop = configurator->loop;
	/*
	 * Destroy the old plugins and interfaces (still marked).
	 *
	 * Take the ones from loop, not configurator.
	 */
	LFOR(plugin, plugin, &loop->plugins)
		if (plugin->mark)
			plugin_destroy(plugin, false);
	LFOR(pcap, interface, &loop->pcap_interfaces)
		if (interface->mark)
			pcap_destroy(interface);
	// Migrate the copied ones, register the new ones.
	LFOR(plugin, plugin, &configurator->plugins)
		if (!plugin->mark)
			for (size_t i = 0; i < loop->timeout_count; i ++)
				if (loop->timeouts[i].context == &plugin->original->context)
					loop->timeouts[i].context = &plugin->context;
	LFOR(pcap, interface, &configurator->pcap_interfaces) {
		epoll_register_pcap(loop, interface, interface->mark ? EPOLL_CTL_ADD : EPOLL_CTL_MOD);
		if (!interface->mark)
			loop_timeout_cancel(loop, interface->watchdog_timer);
		interface->watchdog_timer = loop_timeout_add(loop, PCAP_WATCHDOG_TIME, NULL, interface, pcap_watchdog);
		interface->watchdog_initialized = true;
	}
	// Change the uplink config or copy it
	if (configurator->remote_name)
		uplink_configure(loop->uplink, configurator->remote_name, configurator->remote_service, configurator->login, configurator->password);
	else
		uplink_realloc_config(loop->uplink, configurator->config_pool);
	// Destroy the old configuration and merge the new one
	if (loop->config_pool)
		mem_pool_destroy(configurator->loop->config_pool);
	loop->config_pool = configurator->config_pool;
	loop->pcap_interfaces = configurator->pcap_interfaces;
	loop->plugins = configurator->plugins;
}

void loop_uplink_connected(struct loop *loop) {
	LFOR(plugin, plugin, &loop->plugins)
		plugin_uplink_connected(plugin);
}

void loop_uplink_disconnected(struct loop *loop) {
	LFOR(plugin, plugin, &loop->plugins)
		plugin_uplink_disconnected(plugin);
}

void loop_plugin_reinit(struct context *context) {
	context->loop->reinitialize_plugin = context;
	assert(jump_ready);
	longjmp(jump_env, 1);
}

void loop_uplink_configure(struct loop_configurator *configurator, const char *remote, const char *service, const char *login, const char *password) {
	configurator->remote_name = mem_pool_strdup(configurator->config_pool, remote);
	configurator->remote_service = mem_pool_strdup(configurator->config_pool, service);
	configurator->login = mem_pool_strdup(configurator->config_pool, login);
	configurator->password = mem_pool_strdup(configurator->config_pool, password);
}

uint64_t loop_now(struct loop *loop) {
	return loop->now;
}

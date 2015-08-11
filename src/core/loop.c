/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "loop.h"
#include "mem_pool.h"
#include "util.h"
#include "context.h"
#include "plugin.h"
#include "pluglib.h"
#include "packet.h"
#include "tunable.h"
#include "loader.h"
#include "configure.h"
#include "uplink.h"
#include "trie.h"

#include <signal.h> // for sig_atomic_t
#include <assert.h>
#include <string.h> // Why is memcpy in string?
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

#include <pcap/pcap.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <time.h>
#include <limits.h>
#include <setjmp.h>
#include <stdlib.h>
#include <arpa/inet.h>

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
static volatile sig_atomic_t abort_ready = 0;
static jmp_buf jump_env, abort_env;
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

static void sig_handler(int signal);

static const int signals[] = {
	SIGILL,
	SIGTRAP,
	SIGABRT,
	SIGBUS,
	SIGFPE,
	SIGSEGV,
	SIGALRM,
	SIGTTIN,
	SIGTTOU
};

static void chld_handler(int unused) {
	(void) unused;
}

static void signal_initialize(void) {
	ulog(LLOG_INFO, "Initializing emergency signal handlers\n");
	struct sigaction action = {
		.sa_handler = sig_handler,
		.sa_flags = SA_NODEFER
	};
	for (size_t i = 0; i < sizeof signals / sizeof signals[0]; i ++)
		if (sigaction(signals[i], &action, NULL) == -1)
			die("Sigaction failed for signal %d: %s\n", signals[i], strerror(errno));
	struct sigaction chld_action = {
		.sa_handler = chld_handler,
		.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT | SA_NODEFER
	};
	if (sigaction(SIGCHLD, &chld_action, NULL) == -1)
		die("Can't set action for SIGCHLD: %s\n", strerror(errno));
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
	bool promiscuous;
	struct pcap_sub_interface directions[2];
	size_t offset;
	int datalink;
	size_t watchdog_timer;
	bool watchdog_received,  watchdog_initialized;
	size_t watchdog_missed;
	struct pcap_interface *next;
	bool mark; // Mark for configurator.
	bool in; // Currently processed direction is in (temporary internal mark)
	bool registered; // Registered inside the main loop
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

struct plugin_holder;

struct plugin_fd {
	void (*handler)(struct plugin_fd *fd, uint32_t events);
	int fd;
	void *tag;
	struct plugin_holder *plugin;
	struct plugin_fd *next, *prev;
};

struct trie_data {
	struct config_node config;
	size_t allocated;
};

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
	struct plugin_fd *fd_head, *fd_tail, *fd_unused;
	struct trie *config_trie, *config_candidate;
	struct pluglib_list pluglibs, candidate_pluglibs;
	struct pluglib_node *pluglib_list_recycler;
	bool mark; // Mark for configurator.
	bool active; // Is the plugin activated? Is it allowed to talk to the server?
	size_t failed;
	uint8_t hash[CHALLENGE_LEN / 2];
	unsigned api_version;
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

#define LIST_NODE struct plugin_fd
#define LIST_BASE struct plugin_holder
#define LIST_NAME(X) plugin_fds_##X
#define LIST_HEAD fd_head
#define LIST_TAIL fd_tail
#define LIST_PREV prev
#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_LFOR
#define LIST_WANT_REMOVE
#include "link_list.h"

#define RECYCLER_NODE struct plugin_fd
#define RECYCLER_BASE struct plugin_holder
#define RECYCLER_HEAD fd_unused
#define RECYCLER_NAME(X) plugin_fd_recycler_##X
#include "recycler.h"

/*
 * Generate a wrapper around a plugin callback that:
 *  * Checks it the callback is not NULL (if it is, nothing is called)
 *  * Sets the current context to the one of the plugin (for error handling)
 *  * Calls the callback
 *  * Restores no context and resets the temporary pool
 */
#define GEN_CALL_WRAPPER(NAME) \
static inline void plugin_##NAME(struct plugin_holder *plugin) { \
	if (!plugin->plugin.NAME##_callback) \
		return; \
	current_context = &plugin->context; \
	plugin->plugin.NAME##_callback(&plugin->context); \
	mem_pool_reset(plugin->context.temp_pool); \
	current_context = NULL; \
}\
static inline void plugin_##NAME##_noreset(struct plugin_holder *plugin) { \
	if (!plugin->plugin.NAME##_callback) \
		return; \
	current_context = &plugin->context; \
	plugin->plugin.NAME##_callback(&plugin->context); \
	current_context = NULL; \
}

// The same, with parameter
#define GEN_CALL_WRAPPER_PARAM(NAME, TYPE) \
static inline void plugin_##NAME(struct plugin_holder *plugin, TYPE PARAM) { \
	if (!plugin->plugin.NAME##_callback) \
		return; \
	current_context = &plugin->context; \
	plugin->plugin.NAME##_callback(&plugin->context, PARAM); \
	mem_pool_reset(plugin->context.temp_pool); \
	current_context = NULL; \
}

// And with 2
#define GEN_CALL_WRAPPER_PARAM_2(NAME, TYPE1, TYPE2) \
static inline void plugin_##NAME(struct plugin_holder *plugin, TYPE1 PARAM1, TYPE2 PARAM2) { \
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
GEN_CALL_WRAPPER_PARAM_2(fd, int, void *)
GEN_CALL_WRAPPER_PARAM(config_finish, bool)

static void sig_handler(int signal) {
	jump_signum = signal;
#ifdef DEBUG
	/*
	 * Create a core dump. Do it by copying the process by fork and then
	 * aborting the child. Abort creates a core dump, if it is enabled.
	 */
	if (fork() == 0) {
		sleep(1); // Just wait so we overwrite the core dump created by the abort_safe in loop_run, if we jump there
		abort_safe();
	}
#endif
#ifdef SIGNAL_REINIT
	if (jump_ready && current_context) {
		jump_ready = 0; // Don't try to jump twice in a row if anything goes bad
		// There's a handler
		longjmp(jump_env, 1);
	} else {
#else
	{
#endif
		if (abort_ready)
			longjmp(abort_env, 1);
	}
	abort_safe();
}

static bool plugin_config_check(struct plugin_holder *plugin) {
	if (!plugin->plugin.config_check_callback)
		return true;
	current_context = &plugin->context;
	bool result = plugin->plugin.config_check_callback(&plugin->context);
	mem_pool_reset(plugin->context.temp_pool);
	current_context = NULL;
	return result;
}

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
	// Turns to 1 when we are stopped.
	volatile sig_atomic_t stopped; // We may be stopped from a signal, so not bool
	volatile sig_atomic_t reconfigure; // Set to 1 when there's SIGHUP and we should reconfigure
	volatile sig_atomic_t reconfigure_full; // De-initialize first.
	struct context *reinitialize_plugin; // Please reinitialize this plugin on return from jump
	bool retry_reconfigure_on_failure;
	bool fd_invalidated; // Did we invalidate any FD during this loop iteration? If so, skip the rest.
	struct pluglib_list pluglibs; // All loaded plugin libraries
	// The unused libraries
	struct pluglib_node *pluglib_list_recycler;
	struct pluglib *pluglib_recycler;
};

#define RECYCLER_NODE struct pluglib_node
#define RECYCLER_BASE struct loop
#define RECYCLER_HEAD pluglib_list_recycler
#define RECYCLER_NAME(X) pluglib_list_recycler_##X
#include "recycler.h"

#define RECYCLER_NODE struct pluglib_node
#define RECYCLER_BASE struct plugin_holder
#define RECYCLER_HEAD pluglib_list_recycler
#define RECYCLER_NAME(X) pluglib_plug_recycler_##X
#include "recycler.h"

#define RECYCLER_NODE struct pluglib
#define RECYCLER_BASE struct loop
#define RECYCLER_HEAD pluglib_recycler
#define RECYCLER_NEXT recycler_next
#define RECYCLER_NAME(X) pluglib_recycler_##X
#include "recycler.h"

#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_REMOVE
#define LIST_WANT_LFOR
#include "pluglib_list.h"

struct string_list_node {
	struct string_list_node *next;
	const char *value;
};

struct string_list {
	struct string_list_node *head, *tail;
};

#define LIST_NODE struct string_list_node
#define LIST_BASE struct string_list
#define LIST_NAME(X) string_list_##X
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#include "link_list.h"

// Some stuff for yet uncommited configuration
struct loop_configurator {
	struct loop *loop;
	struct mem_pool *config_pool;
	struct pcap_list pcap_interfaces;
	struct plugin_list plugins;
	const char *remote_name, *remote_service, *login, *password, *cert;
	struct trie *config_trie;
	struct string_list pluglib_names;
	bool need_new_versions;
};

// Handle one packet.
static void packet_handler(struct pcap_interface *interface, const struct pcap_pkthdr *header, const unsigned char *data) {
	struct packet_info info = {
		.length = header->caplen,
		.timestamp = 1000000*(uint64_t)header->ts.tv_sec + (uint64_t)header->ts.tv_usec,
		.data = data,
		.interface = interface->name,
		.direction = interface->in ? DIR_IN : DIR_OUT
	};
	ulog(LLOG_DEBUG_VERBOSE, "Packet of size %zu on interface %s (starting %016llX%016llX, on layer %d) at %" PRIu64 "\n", info.length, interface->name, *(long long unsigned *) info.data, *(1 + (long long unsigned *) info.data), interface->datalink, info.timestamp);
	uc_parse_packet(&info, interface->loop->batch_pool, interface->datalink);
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
	sub->interface->in = sub == &sub->interface->directions[0];
	int result = pcap_dispatch(sub->pcap, MAX_PACKETS, (pcap_handler) packet_handler, (unsigned char *) sub->interface);
	if (result == -1) {
		ulog(LLOG_ERROR, "Error reading packets from PCAP on %s (%s)\n", sub->interface->name, pcap_geterr(sub->pcap));
		sub->interface->loop->retry_reconfigure_on_failure = true;
		self_reconfigure(NULL, NULL, 0); // Try to reconfigure on the next loop iteration
	}
	sub->interface->watchdog_received = true;
	if (result)
		ulog(LLOG_DEBUG_VERBOSE, "Handled %d packets on %s/%p\n", result, sub->interface->name, (void *) sub);
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
	loop->now = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

struct loop *loop_create(void) {
#ifndef NO_SIGNAL_RESCUE
	if (!sig_initialized) {
		signal_initialize();
		sig_initialized = true;
	}
#endif
	ulog(LLOG_INFO, "Creating a main loop\n");
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

// Unlink all pluglibs from a plugin
static void pluglibs_unlink(struct plugin_holder *plugin) {
	LFOR(pluglib_list, lib, &plugin->pluglibs) {
		if (lib->handle && lib->ready && lib->lib)
			lib->lib->ref_count --;
	}
}

static void plugin_destroy(struct plugin_holder *plugin, bool emergency) {
	// Deinit the plugin, if it didn't crash.
	ulog(LLOG_INFO, "Removing plugin %s\n", plugin->plugin.name);
	if (setjmp(jump_env)) {
		ulog(LLOG_ERROR, "Signal %d during plugin finish, doing emergency shutdown instead\n", jump_signum);
		emergency = true;
	}
	jump_ready = true;
	if (!emergency)
		plugin_finish(plugin);
	jump_ready = false;
	size_t pos = 0;
	struct loop *loop = plugin->context.loop;
	// Kill timeouts belonging to the plugin
	while (pos < loop->timeout_count) {
		if (loop->timeouts[pos].context == &plugin->context) {
			// Drop this timeout, as we kill the corresponding plugin
			memmove(loop->timeouts + pos, loop->timeouts + pos + 1, (loop->timeout_count - pos - 1) * sizeof *loop->timeouts);
			loop->timeout_count --;
		} else
			pos ++;
	}
	// Kill FDs belonging to the plugin
	LFOR(plugin_fds, fd, plugin) {
		loop->fd_invalidated = true;
		if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, fd->fd, NULL) == -1)
			ulog(LLOG_ERROR, "Couldn't stop epolling FD %d belonging to removed plugin %s: %s\n", fd->fd, fd->plugin->plugin.name, strerror(errno));
		if (close(fd->fd) == -1)
			ulog(LLOG_ERROR, "Couldn't close FD %d belonging to removed plugin %s: %s\n", fd->fd, fd->plugin->plugin.name, strerror(errno));
	};
	pluglibs_unlink(plugin);
	// Release the memory of the plugin
	pool_list_destroy(&plugin->pool_list);
	mem_pool_destroy(plugin->context.permanent_pool);
	// Unload the library
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

static void config_copy_node(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	(void)key_size;
	struct loop_configurator *configurator = userdata;
	for (size_t i = 0; i < data->config.value_count; i ++)
		loop_set_plugin_opt(configurator, (const char *)key, data->config.values[i]);
}

static void config_copy(struct loop_configurator *configurator, struct plugin_holder *plugin) {
	trie_walk(plugin->config_trie, config_copy_node, configurator, configurator->loop->temp_pool);
}

static void fail_count_reset(struct context *context, void *data, size_t id) {
	// Params are unused
	(void)context;
	(void)id;
	struct loop *loop = data;
	// Reset the counts of failed attempts
	LFOR(plugin, plugin, &loop->plugins) {
		if (plugin->failed) {
			ulog(LLOG_INFO, "Resetting failed count of %s to 0\n", plugin->plugin.name);
			plugin->failed = 0;
		}
	}
	// Another round next time
	loop_timeout_add(loop, FAIL_COUNT_RESET, NULL, loop, fail_count_reset);
}

void loop_run(struct loop *loop) {
	loop_timeout_add(loop, FAIL_COUNT_RESET, NULL, loop, fail_count_reset);
	if (setjmp(abort_env)) {
		abort_ready = 0;
		// Avoid signal loop
		struct sigaction sa = {
			.sa_handler = SIG_DFL
		};
		sigaction(jump_signum, &sa, NULL);
		struct plugin_holder *holder = (struct plugin_holder *) current_context;
#ifdef DEBUG
		assert(!holder || holder->canary == PLUGIN_HOLDER_CANARY);
#endif
		ulog(LLOG_DIE, "Got signal %d with context %p (%s), aborting\n", jump_signum, (void *)current_context, holder ? holder->plugin.name : "<none>");
		// Not ready to jump. Abort.
		abort_safe();
	}
	abort_ready = 1;
	ulog(LLOG_INFO, "Running the main loop\n");
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
				ulog(LLOG_ERROR, "Signal %d in plugin %s (failed %zu times before)\n", jump_signum, holder->plugin.name, failed);
			}
			plugin_destroy(holder, true);
			struct loop_configurator *configurator = loop_config_start(loop);
			holder->mark = false; // This one is already destroyed
			const char *libname = holder->libname; // Make sure it is not picked up
			holder->libname = "";
			LFOR(plugin, plugin, &loop->plugins) {
				config_copy(configurator, plugin);
				if (plugin->mark) { // Copy all the other plugins, and this one if it is to be reinited
					if (!loop_add_plugin(configurator, plugin->libname))
						die("Copy of %s failed\n", plugin->libname);
				} else if (reinit) {
					if (!loop_add_plugin(configurator, libname))
						ulog(LLOG_ERROR, "Reinit of %s failed, aborting plugin\n", libname);
					else
						configurator->plugins.tail->failed = failed + 1;
				}
			}
			LFOR(pcap, interface, &loop->pcap_interfaces) {
				if (!loop_add_pcap(configurator, interface->name, interface->promiscuous))
					die("Copy of %s failed\n", interface->name);
			}
			loop_config_commit(configurator);
			goto REINIT;
		} else {
			ulog(LLOG_ERROR, "Signal %d outside of plugin, aborting\n", jump_signum);
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
		alarm(0); // The epoll_wait can run forever
		int ready = epoll_pwait(loop->epoll_fd, events, MAX_EVENTS, wait_time, &original_mask);
		alarm(60); // But catch any infinite loops in the processing (60 seconds should be enough)
		loop_get_now(loop);
		loop->fd_invalidated = false;
		if (loop->reconfigure) { // We are asked to reconfigure
			jump_ready = 0;
			loop->reconfigure = 0;
			ulog(LLOG_INFO, "Reconfiguring\n");
			if (loop->reconfigure_full)
				// Wipe out current configuration, so we start clean
				loop_config_commit(loop_config_start(loop));
			loop->reconfigure_full = 0;
			if (load_config(loop))
				loop->retry_reconfigure_on_failure = false;
			else {
				ulog(LLOG_ERROR, "Reconfiguration failed, using previous configuration\n");
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
			ulog(LLOG_DEBUG, "Firing timeout %zu at %llu when %zu more timeouts active\n", timeout.id, (long long unsigned) timeout.when, loop->timeout_count);
			timeout.callback(timeout.context, timeout.data, timeout.id);
			mem_pool_reset(loop->temp_pool);
			current_context = NULL;
			timeouts_called = true;
		}
		// Handle events from epoll
		if (ready == -1) {
			if (errno == EINTR) {
				ulog(LLOG_WARN, "epoll_wait on %d interrupted, retry\n", loop->epoll_fd);
				continue;
			}
			die("epoll_wait on %d failed: %s\n", loop->epoll_fd, strerror(errno));
		} else if (!ready && !timeouts_called) {
			// This is strange. We wait for 1 event idefinitelly and get 0
			ulog(LLOG_WARN, "epoll_wait on %d returned 0 events and 0 timeouts\n", loop->epoll_fd);
		} else if (!timeouts_called) { // In case some timeouts happened, get new events. The timeouts could have manipulated existing file descriptors and what we have might be invalid.
			for (size_t i = 0; i < (size_t) ready; i ++) {
				if (loop->fd_invalidated)
					break; // We invalidated a FD. There's a risk it would be one in the batch, which is wrong to call. Get fresh events instead.
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
	abort_ready = 0;
}

static void pcap_destroy(struct pcap_interface *interface) {
	ulog(LLOG_INFO, "Closing both PCAPs on %s\n", interface->name);
	if (interface->watchdog_initialized)
		loop_timeout_cancel(interface->loop, interface->watchdog_timer);
	for (size_t i = 0; i < 2; i ++) {
		int fd = pcap_get_selectable_fd(interface->directions[i].pcap);
		if (interface->registered)
			loop_unregister_fd(interface->loop, fd);
		pcap_close(interface->directions[i].pcap);
	}
}

void loop_destroy(struct loop *loop) {
	ulog(LLOG_INFO, "Releasing the main loop\n");
	// Close all PCAPs
	for (struct pcap_interface *interface = loop->pcap_interfaces.head; interface; interface = interface->next)
		pcap_destroy(interface);
	// Remove all the plugins.
	for (struct plugin_holder *plugin = loop->plugins.head; plugin; plugin = plugin->next)
		plugin_destroy(plugin, false);
	// Close the epoll
	int result = close(loop->epoll_fd);
	assert(result == 0);
	pool_list_destroy(&loop->pool_list);
	// This mempool must be destroyed last, as the loop is allocated from it
	mem_pool_destroy(loop->permanent_pool);
}

// Open one direction of the capture.
static int pcap_create_dir(pcap_t **pcap, pcap_direction_t direction, const char *interface, const char *dir_txt, bool promiscuous) {
	ulog(LLOG_INFO, "Initializing PCAP (%s) on %s\n", dir_txt, interface);
	// Open the pcap
	char errbuf[PCAP_ERRBUF_SIZE];
	*pcap = pcap_create(interface, errbuf);
	if (!*pcap) {
		ulog(LLOG_ERROR, "Can't initialize PCAP (%s) on %s (%s)\n", dir_txt, interface, errbuf);
		return -1;
	}
	// Set parameters.
	int result = pcap_set_promisc(*pcap, promiscuous);
	assert(result == 0); // Can error only on code errors
	result = pcap_set_timeout(*pcap, PCAP_TIMEOUT); // 100 milliseconds
	assert(result == 0);
	result = pcap_set_buffer_size(*pcap, PCAP_BUFFER);
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
			ulog(LLOG_WARN, "PCAP (%s) on %s: %s\n", dir_txt, interface, pcap_geterr(*pcap));
			break;
		default:
			/*
			 * Everything is an error. Even if it wasn't an error, we don't
			 * know it explicitly, so consider it error.
			 */
			ulog(LLOG_ERROR, "PCAP on (%s) %s: %s, closing\n", dir_txt, interface, pcap_geterr(*pcap));
			pcap_close(*pcap);
			return -1;
	}
	// Set it non-blocking. We'll keep switching between pcaps of interfaces and other events.
	if (pcap_setnonblock(*pcap, 1, errbuf) == -1) {
		ulog(LLOG_ERROR, "Can't set PCAP (%s) on %s non-blocking (%s)\n", dir_txt, interface, errbuf);
		pcap_close(*pcap);
		return -1;
	}
	// For some reason, this doesn't work before activated. Maybe it's just filter on the output?
	result = pcap_setdirection(*pcap, direction);
	assert(result == 0);

	// Get the file descriptor for the epoll.
	int fd = pcap_get_selectable_fd(*pcap);
	if (fd == -1) {
		ulog(LLOG_ERROR, "Can't get FD for PCAP (%s) on %s\n", dir_txt, interface);
		pcap_close(*pcap);
		return -1;
	}
	assert(pcap_datalink(*pcap) <= DLT_PFLOG);
	return fd;
}

bool loop_add_pcap(struct loop_configurator *configurator, const char *interface, bool promiscuous) {
	// First, go through the old ones and copy it if is there.
	LFOR(pcap, old, &configurator->loop->pcap_interfaces)
		if (strcmp(interface, old->name) == 0 && old->promiscuous == promiscuous) {
			old->mark = false; // We copy it, don't close it at commit
			struct pcap_interface *new = pcap_append_pool(&configurator->pcap_interfaces, configurator->config_pool);
			*new = *old;
			new->next = NULL;
			new->name = mem_pool_strdup(configurator->config_pool, interface);
			new->directions[PCAP_DIR_IN].interface = new;
			new->directions[PCAP_DIR_OUT].interface = new;
			return true;
		}
	pcap_t *pcap_in;
	int fd_in = pcap_create_dir(&pcap_in, PCAP_D_IN, interface, "in", promiscuous);
	if (fd_in == -1)
		return false; // Error already reported

	pcap_t *pcap_out;
	int fd_out = pcap_create_dir(&pcap_out, PCAP_D_OUT, interface, "out", promiscuous);
	if (fd_out == -1) {
		pcap_close(pcap_in);
		return false;
	}

	// Put the PCAP into the new configuration loop.
	struct pcap_interface *new = pcap_append_pool(&configurator->pcap_interfaces, configurator->config_pool);
	*new = (struct pcap_interface) {
		.loop = configurator->loop,
		.name = mem_pool_strdup(configurator->config_pool, interface),
		.promiscuous = promiscuous,
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
				result[pos ++] += ps.ps_ifdrop;
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

void loop_set_plugin_opt(struct loop_configurator *configurator, const char *name, const char *value) {
	ulog(LLOG_DEBUG, "Option %s: %s\n", name, value);
	if (!configurator->config_trie)
		configurator->config_trie = trie_alloc(configurator->config_pool);
	struct trie_data **node = trie_index(configurator->config_trie, (const uint8_t *)name, strlen(name));
	if (!*node) {
		*node = mem_pool_alloc(configurator->config_pool, sizeof **node);
		memset(*node, 0, sizeof **node);
	}
	if ((*node)->allocated == (*node)->config.value_count) {
		size_t new_alloc = 2 + 3 * (*node)->allocated;
		const char **new_values = mem_pool_alloc(configurator->config_pool, new_alloc * sizeof *new_values);
		memcpy(new_values, (*node)->config.values, (*node)->config.value_count * sizeof *new_values);
		(*node)->config.values = new_values;
		(*node)->allocated = new_alloc;
	}
	(*node)->config.values[(*node)->config.value_count ++] = mem_pool_strdup(configurator->config_pool, value);
}

void loop_set_pluglib(struct loop_configurator *configurator, const char *libname) {
	ulog(LLOG_DEBUG, "Need plugin library %s\n", libname);
	string_list_append_pool(&configurator->pluglib_names, configurator->loop->temp_pool)->value = mem_pool_strdup(configurator->loop->temp_pool, libname);
}

const struct config_node *loop_plugin_option_get(struct context *context, const char *name) {
	struct plugin_holder *holder = (struct plugin_holder *) context;
#ifdef DEBUG
	assert(holder->canary == PLUGIN_HOLDER_CANARY);
#endif
	struct trie *config = holder->config_candidate ? holder->config_candidate : holder->config_trie;
	assert(config); // We really should have at least some config - at least the libname must be there
	struct trie_data *data = trie_lookup(config, (const uint8_t *)name, strlen(name));
	if (data) {
		return &data->config;
	} else {
		return NULL;
	}
}

static bool pluglib_install(struct plugin_holder *plugin, const char *libname, bool live) {
	ulog(LLOG_DEBUG, "Loading library %s\n", libname);
	// Prepare the structure to hold the loaded library
	struct loop *loop = plugin->context.loop;
	struct pluglib_node *node = pluglib_list_recycler_get(loop, loop->permanent_pool);
	memset(node, 0, sizeof *node);
	pluglib_list_insert_after(&loop->pluglibs, node, loop->pluglibs.tail);
	node->lib = pluglib_recycler_get(loop, loop->permanent_pool);
	memset(node->lib, 0, sizeof *node->lib);
	// Load the library
	node->handle = pluglib_load(libname, node->lib, node->hash);
	if (!node->handle) {
		ulog(LLOG_ERROR, "Couldn't find dependent library %s\n", libname);
		return false;
	}
	node->lib->ref_count = 0;
	node->lib->recycler_next = NULL;
	node->ready = true;
	// Find if we need it or there's a compatible one already loaded
	struct pluglib_node *found = NULL;
	LFOR(pluglib_list, candidate, &loop->pluglibs) {
		if (!node->handle)
			continue; // No library loaded here, garbage that's left from something. It'll get removed soon, but ignore it now.
		if (candidate == node) {
			ulog(LLOG_DEBUG, "No other candidate but the library itself found\n");
			found = candidate;
			break;
		}
		if (memcmp(candidate->hash, node->hash, sizeof node->hash) == 0) {
			ulog(LLOG_DEBUG, "The exact same library is already loaded\n");
			found = candidate;
			break;
		}
		if (strcmp(candidate->lib->name, node->lib->name) == 0 &&
				candidate->lib->compat == node->lib->compat &&
				candidate->lib->version >= node->lib->version) {
			ulog(LLOG_DEBUG, "Compatible library %s (compat %zu, version %zu) found\n", candidate->lib->name, candidate->lib->compat, candidate->lib->version);
			found = candidate;
			break;
		}
	}
	assert(found); // It must find at least itself
	// We don't clean the library now, even if we found better candidate. It'll get removed later on cleanup.
	struct pluglib_node *plugin_node = pluglib_plug_recycler_get(plugin, plugin->context.permanent_pool);
	*plugin_node = *found;
	if (live) {
		pluglib_list_insert_after(&plugin->pluglibs, plugin_node, plugin->pluglibs.tail);
		found->lib->ref_count ++;
	} else
		pluglib_list_insert_after(&plugin->candidate_pluglibs, plugin_node, plugin->candidate_pluglibs.tail);
	return true;
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
			// Move the configuration into the plugin and check it
			new->config_candidate = configurator->config_trie;
			configurator->config_trie = NULL;
			memset(&new->candidate_pluglibs, 0, sizeof new->candidate_pluglibs);
			if (configurator->pluglib_names.head) {
				if (new->api_version >= 1) {
					// Reconfigure the libraries. If they are not set, ignore.
					LFOR(string_list, libname, &configurator->pluglib_names)
						if (!pluglib_install(new, libname->value, false)) {
							memset(&configurator->pluglib_names, 0, sizeof configurator->pluglib_names);
							return false;
						}
					memset(&configurator->pluglib_names, 0, sizeof configurator->pluglib_names);
					if (!pluglib_check_functions(&new->pluglibs, new->plugin.imports))
						return false;
				} else {
					ulog(LLOG_ERROR, "Pluglibs for reused plugin with api version 0 %s\n", new->plugin.name);
					return false;
				}
			}
			return plugin_config_check(new);
		}
	// Load the plugin
	struct plugin plugin;
	uint8_t hash[CHALLENGE_LEN / 2];
	unsigned api_version;
	void *plugin_handle = plugin_load(libname, &plugin, hash, &api_version);
	if (!plugin_handle)
		return false;
	ulog(LLOG_INFO, "Installing plugin %s with api version %u\n", plugin.name, api_version);
	struct mem_pool *permanent_pool = mem_pool_create(plugin.name);
	assert(!jump_ready);
	struct plugin_holder *new = mem_pool_alloc(configurator->config_pool, sizeof *new);
	memset(new, 0, sizeof *new);
	if (setjmp(jump_env)) {
		ulog(LLOG_ERROR, "Signal %d during plugin initialization, aborting load\n", jump_signum);
		goto ERROR;
	}
	jump_ready = 1;
	/*
	 * Each plugin gets its own permanent pool (since we'd delete that one with the plugin),
	 * but we can reuse the temporary pool.
	 */
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
		.config_candidate = configurator->config_trie,
		.mark = true,
		.api_version = api_version
	};
	configurator->config_trie = NULL;
	memcpy(new->hash, hash, sizeof hash);
	// Copy the name (it may be temporary), from the plugin's own pool
	new->plugin.name = mem_pool_strdup(configurator->config_pool, plugin.name);
	if (new->api_version >= 1) {
		LFOR(string_list, libname, &configurator->pluglib_names)
			if (!pluglib_install(new, libname->value, true))
				goto ERROR;
		memset(&configurator->pluglib_names, 0, sizeof configurator->pluglib_names);
		if (!pluglib_resolve_functions(&new->pluglibs, new->plugin.imports))
			goto ERROR;
	} else if (configurator->pluglib_names.head) {
		ulog(LLOG_ERROR, "Pluglibs for plugin with api version 0 %s\n", new->plugin.name);
		goto ERROR;
	}
	plugin_init(new);
	jump_ready = 0;
	// Store the plugin structure.
	plugin_insert_after(&configurator->plugins, new, configurator->plugins.tail);
	configurator->need_new_versions = true;
	return plugin_config_check(new);
ERROR:
	jump_ready = 0;
	pluglibs_unlink(new);
	mem_pool_destroy(permanent_pool);
	plugin_unload(plugin_handle);
	memset(&configurator->pluglib_names, 0, sizeof configurator->pluglib_names);
	return false;
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

void loop_unregister_fd(struct loop *loop, int fd) {
	if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, fd, NULL) == -1)
		die("Couldn't remove fd %d from epoll %d (%s)\n", fd, loop->epoll_fd, strerror(errno));
	loop->fd_invalidated = true;
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
	assert(loop->uplink);
	LFOR(plugin, plugin, &loop->plugins)
		if (strcmp(plugin->plugin.name, name) == 0) {
			// Skip inactive plugins. There might, in theory, be another active version with the same name, so don't abort yet.
			if (!plugin->active)
				continue;
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

bool loop_plugin_active(const struct context *context) {
	const struct plugin_holder *holder = (struct plugin_holder *) context;
#ifdef DEBUG
	assert(holder->canary == PLUGIN_HOLDER_CANARY);
#endif
	return holder->active;
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
	 * timed out a long time ago. But we still check it is OK and fix it if not.
	 */
	static size_t id = 0;
	bool ok;
	do {
		ok = true;
		id ++;
		for (size_t i = 0; i <= loop->timeout_count; i ++) {
			if (i == pos)
				continue;
			if (loop->timeouts[i].id == id) {
				ok = false;
				break;
			}
		}
	} while (!ok);
	loop->timeouts[pos] = (struct timeout) {
		.when = when,
		.callback = callback,
		.context = context,
		.data = data,
		.id = id
	};
	ulog(LLOG_DEBUG, "Adding timeout for %lu milliseconds, expected to fire at %llu, now %llu as ID %zu\n", (unsigned long) after,  (unsigned long long) when, (unsigned long long) loop->now, loop->timeouts[pos].id);
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

static void pluglibs_cleanup(struct loop *loop) {
	struct pluglib_node *lib = loop->pluglibs.head;
	while (lib) {
		if (lib->lib && (!lib->ready || lib->lib->ref_count == 0)) {
			pluglib_recycler_release(loop, lib->lib);
			lib->lib = NULL;
		}
		if (!lib->lib && lib->handle) {
			plugin_unload(lib->handle);
			lib->handle = NULL;
		}
		if (!lib->handle) {
			struct pluglib_node *tmp = lib;
			lib = lib->next;
			pluglib_list_remove(&loop->pluglibs, tmp);
			pluglib_list_recycler_release(loop, tmp);
		} else
			lib = lib->next;
	}
}

void loop_config_abort(struct loop_configurator *configurator) {
	/*
	 * Destroy all the newly-created plugins and interfaces (marked)
	 *
	 * Select the ones from the configurator, not loop!
	 *
	 * Also, remove config candidate from the in-loop plugins.
	 */
	LFOR(plugin, plugin, &configurator->plugins)
		if (plugin->mark) {
			plugin_destroy(plugin, false);
		} else {
			plugin->config_candidate = NULL;
			plugin_config_finish(plugin, false);
			// Remove the candidate list
			struct pluglib_node *lib = plugin->candidate_pluglibs.head;
			while (lib) {
				struct pluglib_node *tmp = lib;
				lib = lib->next;
				pluglib_plug_recycler_release(plugin, tmp);
			}
			memset(&plugin->candidate_pluglibs, 0, sizeof plugin->candidate_pluglibs);
		}
	pluglibs_cleanup(configurator->loop);
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
		ulog(LLOG_WARN, "No data on interface %s in a long time\n", interface->name);
		if (interface->watchdog_missed >= WATCHDOG_MISSED_COUNT) {
			ulog(LLOG_ERROR, "Too many missed intervals of data on %s, doing full reconfigure in attempt to recover from unknown external errors\n", interface->name);
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

static const char *libname(const struct plugin_holder *plugin) {
	const char *libname = rindex(plugin->libname, '/');
	if (libname)
		libname ++;
	else
		libname = plugin->libname;
	return libname;
}

// TODO: Send pluglibs too
static void send_plugin_versions(struct loop *loop) {
	ulog(LLOG_DEBUG, "Sending list of plugins\n");
	size_t message_size = 0;
	LFOR(plugin, plugin, &loop->plugins) {
		message_size += 2*sizeof(uint32_t) + sizeof(uint16_t) + strlen(plugin->plugin.name) + sizeof plugin->hash + strlen(libname(plugin)) + 1; // Size prefix of the string and the plugin version
	}
	uint8_t *message = mem_pool_alloc(loop->temp_pool, message_size);
	uint8_t *pos = message;
	size_t rest = message_size;
	LFOR(plugin, plugin, &loop->plugins) {
		uplink_render_string(plugin->plugin.name, strlen(plugin->plugin.name), &pos, &rest);
		uint16_t version = htons(plugin->plugin.version);
		assert(rest >= sizeof version);
		memcpy(pos, &version, sizeof version);
		rest -= sizeof version;
		pos += sizeof version;
		memcpy(pos, plugin->hash, sizeof plugin->hash);
		rest -= sizeof plugin->hash;
		pos += sizeof plugin->hash;
		const char *ln = libname(plugin);
		uplink_render_string(ln, strlen(ln), &pos, &rest);
		*pos = plugin->active ? 'A' : 'I';
		pos ++;
		rest --;
	}
	assert(rest == 0);
	uplink_send_message(loop->uplink, 'V', message, message_size);
}

void loop_config_commit(struct loop_configurator *configurator) {
	struct loop *loop = configurator->loop;
	/*
	 * Destroy the old plugins and interfaces (still marked).
	 *
	 * Take the ones from loop, not configurator.
	 */
	LFOR(plugin, plugin, &loop->plugins)
		if (plugin->mark) {
			plugin_destroy(plugin, false);
			configurator->need_new_versions = true;
		}
	LFOR(pcap, interface, &loop->pcap_interfaces)
		if (interface->mark)
			pcap_destroy(interface);
	// Migrate the copied ones, register the new ones.
	LFOR(plugin, plugin, &configurator->plugins)
		if (!plugin->mark) {
			for (size_t i = 0; i < loop->timeout_count; i ++)
				if (loop->timeouts[i].context == &plugin->original->context)
					loop->timeouts[i].context = &plugin->context;
			// Update pointers inside its FDs. The FDs are allocated from the plugin's pool, so they survive, but the kept context/plugin holder there would be outdated.
			LFOR(plugin_fds, fd_holder, plugin)
				fd_holder->plugin = plugin;
			// Migrate to new pluglibs
			if (plugin->candidate_pluglibs.head) {
				// We can do this, it may drop the refcounts to 0 on libraries we may use later, but we won't clean it now anyway.
				pluglibs_unlink(plugin);
				// Drop the old list
				struct pluglib_node *lib = plugin->pluglibs.head;
				while (lib) {
					struct pluglib_node *tmp = lib;
					lib = lib->next;
					pluglib_plug_recycler_release(plugin, tmp);
				}
				// Move the new one
				plugin->pluglibs = plugin->candidate_pluglibs;
				memset(&plugin->candidate_pluglibs, 0, sizeof plugin->candidate_pluglibs);
				// Increase the refcounts
				LFOR(pluglib_list, lib, &plugin->pluglibs) {
					assert(lib->lib);
					lib->lib->ref_count ++;
				}
				// Resolve the symbols from new libraries, overwriting the old ones.
				if (!pluglib_resolve_functions(&plugin->pluglibs, plugin->plugin.imports))
					die("Failed to resolve functions for plugin %s despite checking first\n", plugin->plugin.name);
			}
		}
	LFOR(pcap, interface, &configurator->pcap_interfaces) {
		epoll_register_pcap(loop, interface, interface->mark ? EPOLL_CTL_ADD : EPOLL_CTL_MOD);
		interface->registered = true;
		if (!interface->mark)
			loop_timeout_cancel(loop, interface->watchdog_timer);
		interface->watchdog_timer = loop_timeout_add(loop, PCAP_WATCHDOG_TIME, NULL, interface, pcap_watchdog);
		interface->watchdog_initialized = true;
	}
	// Change the uplink config or copy it
	if (loop->uplink) {
		if (configurator->remote_name)
			uplink_configure(loop->uplink, configurator->remote_name, configurator->remote_service, configurator->login, configurator->password, configurator->cert);
		else
			uplink_realloc_config(loop->uplink, configurator->config_pool);
	}
	// Destroy the old configuration and merge the new one
	if (loop->config_pool)
		mem_pool_destroy(configurator->loop->config_pool);
	loop->config_pool = configurator->config_pool;
	loop->pcap_interfaces = configurator->pcap_interfaces;
	loop->plugins = configurator->plugins;
	// Initialize/commit configuration of the plugins
	LFOR(plugin, plugin, &loop->plugins) {
		plugin->config_trie = plugin->config_candidate;
		plugin->config_candidate = NULL;
		plugin_config_finish(plugin, true);
	}
	// Clean up unused pluglibs
	pluglibs_cleanup(configurator->loop);
	if (configurator->need_new_versions && uplink_connected(loop->uplink))
		send_plugin_versions(loop);
}

void loop_uplink_connected(struct loop *loop) {
	send_plugin_versions(loop);
}

void loop_uplink_disconnected(struct loop *loop) {
	LFOR(plugin, plugin, &loop->plugins) {
		if (plugin->active)
			plugin_uplink_disconnected(plugin);
		plugin->active = false;
	}
}

void loop_plugin_reinit(struct context *context) {
	context->loop->reinitialize_plugin = context;
	assert(jump_ready);
	longjmp(jump_env, 1);
}

void loop_uplink_configure(struct loop_configurator *configurator, const char *remote, const char *service, const char *login, const char *password, const char *cert) {
	configurator->remote_name = mem_pool_strdup(configurator->config_pool, remote);
	configurator->remote_service = mem_pool_strdup(configurator->config_pool, service);
	configurator->login = login ? mem_pool_strdup(configurator->config_pool, login) : NULL;
	configurator->password = password ? mem_pool_strdup(configurator->config_pool, password) : NULL;
	configurator->cert = cert ? mem_pool_strdup(configurator->config_pool, cert) : NULL;
}

uint64_t loop_now(struct loop *loop) {
	return loop->now;
}

static void plugin_fd_event(struct plugin_fd *fd, uint32_t events) {
	(void) events;
	ulog(LLOG_DEBUG, "Event on fd %d of plugin %s\n", fd->fd, fd->plugin->plugin.name);
	plugin_fd(fd->plugin, fd->fd, fd->tag);
}

void loop_plugin_register_fd(struct context *context, int fd, void *tag) {
	struct plugin_holder *holder = (struct plugin_holder *) context;
#ifdef DEBUG
	assert(holder->canary == PLUGIN_HOLDER_CANARY);
#endif
	struct plugin_fd *handler = plugin_fd_recycler_get(holder, context->permanent_pool);
	*handler = (struct plugin_fd) {
		.handler = plugin_fd_event,
		.fd = fd,
		.tag = tag,
		.plugin = holder
	};
	plugin_fds_insert_after(holder, handler, holder->fd_tail);
	loop_register_fd(context->loop, fd, (struct epoll_handler*)handler);
	ulog(LLOG_DEBUG, "Watching fd %d of plugin %s\n", fd, holder->plugin.name);
}

void loop_plugin_unregister_fd(struct context *context, int fd) {
	struct plugin_holder *holder = (struct plugin_holder *) context;
#ifdef DEBUG
	assert(holder->canary == PLUGIN_HOLDER_CANARY);
#endif
	LFOR(plugin_fds, handler, holder)
		if (handler->fd == fd) {
			// Found the one, remove it (and let caller close it)
			loop_unregister_fd(context->loop, fd);
			plugin_fds_remove(holder, handler);
			plugin_fd_recycler_release(holder, handler);
			ulog(LLOG_DEBUG, "Unregistered fd %d of plugin %s\n", fd, holder->plugin.name);
			return;
		}
	ulog(LLOG_WARN, "Asked to unregister plugin's %s fd %d, but it is not present; ignoring request\n", holder->plugin.name, fd);
}

pid_t loop_fork(struct loop *loop) {
	pid_t result = fork();
	if (result == 0) {
		// The child. Do bunch of closing.
		jump_ready = 0;
		abort_ready = 0;
		LFOR(plugin, plugin, &loop->plugins) {
			LFOR(plugin_fds, handler, plugin) {
				assert(handler->fd != -1);
				close(handler->fd);
			}
		}
		LFOR(pcap, interface, &loop->pcap_interfaces) {
			for (size_t i = 0; i < 2; i ++)
				pcap_close(interface->directions[i].pcap);
		}
		if (loop->uplink)
			uplink_close(loop->uplink);
		close(loop->epoll_fd);
	}
	return result;
}

void loop_plugin_activation(struct loop *loop, struct plugin_activation *plugins, size_t count) {
	bool changed = false;
	for (size_t i = 0; i < count; i ++) {
		struct plugin_holder *candidate = NULL;
		LFOR(plugin, plugin, &loop->plugins) {
			if (strcmp(plugin->plugin.name, plugins[i].name) == 0 && memcmp(plugin->hash, plugins[i].hash, sizeof plugins[i].hash) == 0) {
				candidate = plugin;
				break;
			}
		}
		if (candidate) {
			if (plugins[i].activate != candidate->active) {
				changed = true;
				candidate->active = plugins[i].activate;
				if (plugins[i].activate) {
					ulog(LLOG_INFO, "Activating plugin %s\n", plugins[i].name);
					plugin_uplink_connected_noreset(candidate);
				} else {
					ulog(LLOG_INFO, "Deactivating plugin %s\n", plugins[i].name);
					plugin_uplink_disconnected_noreset(candidate);
				}
			}
		} else {
			size_t len = strlen(plugins[i].name);
			size_t size = 1 /* Error header */ + 4 /* String length */ + len + sizeof plugins[i].hash;
			uint8_t *buffer = mem_pool_alloc(loop->temp_pool, size);
			uint8_t *pos = buffer;
			size_t rest = size;
			*buffer = 'A'; // Error during activation
			buffer ++;
			rest --;
			uplink_render_string(plugins[i].name, len, &pos, &rest);
			assert(rest == sizeof plugins[i].hash);
			memcpy(pos, plugins[i].hash, sizeof plugins[i].hash);
			uplink_send_message(loop->uplink, 'E', buffer, size);
		}
	}
	if (changed)
		send_plugin_versions(loop);
}

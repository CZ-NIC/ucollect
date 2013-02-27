#include "loop.h"
#include "mem_pool.h"
#include "util.h"
#include "context.h"
#include "plugin.h"
#include "packet.h"
#include "address.h"
#include "tunable.h"
#include "loader.h"

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

struct pcap_interface {
	/*
	 * This will be always set to pcap_read. Trick to make the epollhandling
	 * simpler ‒ we put this struct directly as the user data to epoll and the
	 * generic handler calls the handler found, no matter what type it is.
	 *
	 * This item must be first in the data structure. It'll be then casted to
	 * the epoll_handler, which contains a function pointer as the first element.
	 */
	void (*handler)(struct pcap_interface *interface, uint32_t events);
	// Link back to the loop owning this pcap. For epoll handler.
	struct loop *loop;
	const char *name;
	pcap_t *pcap;
	struct address_list *local_addresses;
	int fd;
	size_t offset;
	struct pcap_interface *next;
	bool mark; // Mark for configurator.
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
};

struct plugin_list {
	struct plugin_holder *head, *tail;
};

#define LIST_NODE struct plugin_holder
#define LIST_BASE struct plugin_list
#define LIST_NAME(X) plugin_##X
#define LIST_WANT_APPEND_POOL
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
	sig_atomic_t stopped; // We may be stopped from a signal, so not bool
};

// Some stuff for yet uncommited configuration
struct loop_configurator {
	struct loop *loop;
	struct mem_pool *config_pool;
	struct pcap_list pcap_interfaces;
	struct plugin_list plugins;
};

// Handle one packet.
static void packet_handler(struct pcap_interface *interface, const struct pcap_pkthdr *header, const unsigned char *data) {
	struct packet_info info = {
		.length = header->caplen - interface->offset,
		.data = data + interface->offset,
		.interface = interface->name
	};
	ulog(LOG_DEBUG_VERBOSE, "Packet of size %zu on interface %s\n", info.length, interface->name);
	parse_packet(&info, interface->local_addresses, interface->loop->batch_pool);
	LFOR(struct plugin_holder, plugin, interface->loop->plugins)
		plugin_packet(plugin, &info);
}

static void pcap_read(struct pcap_interface *interface, uint32_t unused) {
	(void) unused;
	ulog(LOG_DEBUG_VERBOSE, "Read on interface %s\n", interface->name);
	int result = pcap_dispatch(interface->pcap, MAX_PACKETS, (pcap_handler) packet_handler, (unsigned char *) interface);
	if (result == -1)
		die("Error reading packets from PCAP on %s (%s)\n", interface->name, pcap_geterr(interface->pcap));
	ulog(LOG_DEBUG_VERBOSE, "Handled %d packets on %s\n", result, interface->name);
}

static void epoll_register_pcap(struct loop *loop, struct pcap_interface *interface, int op) {
	struct epoll_event event = {
		.events = EPOLLIN,
		.data = {
			.ptr = interface
		}
	};
	if (epoll_ctl(loop->epoll_fd, op, interface->fd, &event) == -1)
		die("Can't register PCAP fd %d of %s to epoll fd %d (%s)\n", interface->fd, interface->name, loop->epoll_fd, strerror(errno));
}

struct loop *loop_create() {
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
	return result;
}

void loop_break(struct loop *loop) {
	loop->stopped = 1;
}

static void loop_get_now(struct loop *loop) {
	struct timespec ts;
	/*
	 * CLOC_MONOTONIC can go backward or jump if admin adjusts date.
	 * But the CLOCK_MONOTONIC_RAW doesn't seem to be available in uclibc.
	 * Any better alternative?
	 */
	if(clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		die("Couldn't get time (%s)\n", strerror(errno));
	loop->now = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void loop_run(struct loop *loop) {
	ulog(LOG_INFO, "Running the main loop\n");
	loop_get_now(loop);
	while (!loop->stopped) {
		struct epoll_event events[MAX_EVENTS];
		// TODO: Support for reconfigure signal (epoll_pwait then).
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
		int ready = epoll_wait(loop->epoll_fd, events, MAX_EVENTS, wait_time);
		loop_get_now(loop);
		// Handle timeouts.
		bool timeouts_called = false;
		while (loop->timeout_count && loop->timeouts[0].when <= loop->now) {
			// Take it out before calling. The callback might manipulate timeouts.
			struct timeout timeout = loop->timeouts[0];
			// Suboptimal, but there should be only few timeouts and not often
			memmove(loop->timeouts, loop->timeouts + 1, (-- loop->timeout_count) * sizeof *loop->timeouts);
			current_context = timeout.context;
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
}

static void pcap_destroy(struct pcap_interface *interface) {
	ulog(LOG_INFO, "Closing PCAP on %s\n", interface->name);
	pcap_close(interface->pcap);
}

static void plugin_destroy(struct plugin_holder *plugin) {
	ulog(LOG_INFO, "Removing plugin %s\n", plugin->plugin.name);
	plugin_finish(plugin);
	pool_list_destroy(&plugin->pool_list);
	mem_pool_destroy(plugin->context.permanent_pool);
	plugin_unload(plugin->plugin_handle);
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
		plugin_destroy(plugin);
	pool_list_destroy(&loop->pool_list);
	// This mempool must be destroyed last, as the loop is allocated from it
	mem_pool_destroy(loop->permanent_pool);
}

// How much data should be skipped on each type of pcap. Borrowed from the DNS traffic analyser project.
static const size_t ip_offset_table[] =
{
	[DLT_LOOP] = 4,
	[DLT_NULL] = 4,    /* BSD LoopBack       */
	[DLT_EN10MB] = 14, /* EthernetII, I hope */
	[DLT_RAW] = 0,     /* RAW IP             */
	[DLT_PFLOG] = 28,  /* BSD pflog          */
};

bool loop_add_pcap(struct loop_configurator *configurator, const char *interface) {
	// First, go through the old ones and copy it if is there.
	LFOR(struct pcap_interface, old, configurator->loop->pcap_interfaces)
		if (strcmp(interface, old->name) == 0) {
			old->mark = false; // We copy it, don't close it at commit
			struct pcap_interface *new = pcap_append_pool(&configurator->pcap_interfaces, configurator->config_pool);
			*new = *old;
			new->next = NULL;
			new->local_addresses = address_list_create(configurator->config_pool);
			new->name = mem_pool_strdup(configurator->config_pool, interface);
			return true;
		}
	ulog(LOG_INFO, "Initializing PCAP on %s\n", interface);
	// Open the pcap
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_create(interface, errbuf);
	if (!pcap) {
		ulog(LOG_ERROR, "Can't initialize PCAP on %s (%s)\n", interface, errbuf);
		return false;
	}
	// Set parameters.
	int result = pcap_set_promisc(pcap, 1);
	assert(result == 0); // Can error only on code errors
	result = pcap_set_timeout(pcap, PCAP_TIMEOUT); // One second
	assert(result == 0);
	pcap_set_buffer_size(pcap, PCAP_BUFFER);
	assert(result == 0);

	// TODO: Some filters?

	// Activate it
	result = pcap_activate(pcap);
	switch (result) {
		// We need to manually distinguish what are errors, what warnings, etc.
		case 0: // All OK
			break;
		case PCAP_WARNING_PROMISC_NOTSUP:
		case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
		case PCAP_WARNING:
			// These are just warnings. Display them, but continue.
			ulog(LOG_WARN, "PCAP on %s: %s\n", interface, pcap_geterr(pcap));
			break;
		default:
			/*
			 * Everything is an error. Even if it wasn't an error, we don't
			 * know it explicitly, so consider it error.
			 */
			ulog(LOG_ERROR, "PCAP on %s: %s, closing\n", interface, pcap_geterr(pcap));
			pcap_close(pcap);
			return false;
	}
	// Set it non-blocking. We'll keep switching between pcaps of interfaces and other events.
	if (pcap_setnonblock(pcap, 1, errbuf) == -1) {
		ulog(LOG_ERROR, "Can't set PCAP on %s non-blocking (%s)\n", interface, errbuf);
		pcap_close(pcap);
		return false;
	}

	// Get the file descriptor for the epoll.
	int fd = pcap_get_selectable_fd(pcap);
	if (fd == -1) {
		ulog(LOG_ERROR, "Can't get FD for PCAP on %s\n", interface);
		pcap_close(pcap);
		return false;
	}

	// Put the PCAP into the new configuration loop.
	struct pcap_interface *new = pcap_append_pool(&configurator->pcap_interfaces, configurator->config_pool);
	assert(pcap_datalink(pcap) <= DLT_PFLOG);
	*new = (struct pcap_interface) {
		.handler = pcap_read,
		.loop = configurator->loop,
		.name = mem_pool_strdup(configurator->config_pool, interface),
		.pcap = pcap,
		.local_addresses = address_list_create(configurator->config_pool),
		.fd = fd,
		.offset = ip_offset_table[pcap_datalink(pcap)],
		.mark = true
	};
	return true;
}

bool loop_pcap_add_address(struct loop_configurator *configurator, const char *address) {
	assert(configurator->pcap_interfaces.tail);
	return address_list_add_parsed(configurator->pcap_interfaces.tail->local_addresses, address, true);
}

bool loop_add_plugin(struct loop_configurator *configurator, const char *libname) {
	// Look for existing plugin first
	LFOR(struct plugin_holder, old, configurator->loop->plugins)
		if (strcmp(old->libname, libname) == 0) {
			old->mark = false; // We copy it, so don't delete after commit
			struct plugin_holder *new = plugin_append_pool(&configurator->plugins, configurator->config_pool);
			*new = *old;
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
	// Store the plugin structure.
	struct plugin_holder *new = plugin_append_pool(&configurator->plugins, configurator->config_pool);
	/*
	 * Each plugin gets its own permanent pool (since we'd delete that one with the plugin),
	 * but we can reuse the temporary pool.
	 */
	*new = (struct plugin_holder) {
		.context = {
			.temp_pool = configurator->loop->temp_pool,
			.permanent_pool = mem_pool_create(plugin.name),
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
	pool_append_pool(&new->pool_list, new->context.permanent_pool)->pool = new->context.permanent_pool;
	// Copy the name (it may be temporary), from the plugin's own pool
	new->plugin.name = mem_pool_strdup(configurator->config_pool, plugin.name);
	plugin_init(new);
	return true;
}

void loop_uplink_set(struct loop *loop, struct uplink *uplink) {
	assert(!loop->uplink);
	loop->uplink = uplink;
	LFOR(struct plugin_holder, plugin, loop->plugins)
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
	LFOR(struct plugin_holder, plugin, loop->plugins)
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
	size_t when = loop->now + after;
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
	LFOR(struct plugin_holder, plugin, loop->plugins)
		plugin->mark = true;
	LFOR(struct pcap_interface, interface, loop->pcap_interfaces)
		interface->mark = true;
	return result;
}

void loop_config_abort(struct loop_configurator *configurator) {
	/*
	 * Destroy all the newly-created plugins and interfaces (marked)
	 *
	 * Select the ones from the configurator, not loop!
	 */
	LFOR(struct plugin_holder, plugin, configurator->plugins)
		if (plugin->mark)
			plugin_destroy(plugin);
	LFOR(struct pcap_interface, interface, configurator->pcap_interfaces)
		if (interface->mark)
			pcap_destroy(interface);
	// And delete all the memory
	mem_pool_destroy(configurator->config_pool);
}

void loop_config_commit(struct loop_configurator *configurator) {
	struct loop *loop = configurator->loop;
	/*
	 * Destroy the old plugins and interfaces (still marked).
	 *
	 * Take the ones from loop, not configurator.
	 */
	LFOR(struct plugin_holder, plugin, loop->plugins)
		if (plugin->mark)
			plugin_destroy(plugin);
	LFOR(struct pcap_interface, interface, loop->pcap_interfaces)
		if (interface->mark)
			pcap_destroy(interface);
	// Migrate the copied ones, register the new ones.
	LFOR(struct plugin_holder, plugin, configurator->plugins)
		if (!plugin->mark)
			for (size_t i = 0; i < loop->timeout_count; i ++)
				if (loop->timeouts[i].context == &plugin->original->context)
					loop->timeouts[i].context = &plugin->context;
	LFOR(struct pcap_interface, interface, configurator->pcap_interfaces)
		epoll_register_pcap(loop, interface, interface->mark ? EPOLL_CTL_ADD : EPOLL_CTL_MOD);
	// Destroy the old configuration and merge the new one
	if (loop->config_pool)
		mem_pool_destroy(configurator->loop->config_pool);
	loop->config_pool = configurator->config_pool;
	loop->pcap_interfaces = configurator->pcap_interfaces;
	loop->plugins = configurator->plugins;
}

#include "loop.h"
#include "mem_pool.h"
#include "util.h"
#include "context.h"
#include "plugin.h"

#include <signal.h> // for sig_atomic_t
#include <assert.h>
#include <string.h> // Why is memcpy in string?
#include <errno.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <sys/epoll.h>

// TODO: Should these be configurable? Runtime or compile time?
#define MAX_EVENTS 10
#define MAX_PACKETS 100
#define PCAP_TIMEOUT 1000
#define PCAP_BUFFER 655360

struct epoll_handler {
	void (*handler)(void *);
};

struct pcap_interface {
	/*
	 * This will be always set to pcap_read. Trick to make the epollhandling
	 * simpler ‒ we put this struct directly as the user data to epoll and the
	 * generic handler calls the handler found, no matter what type it is.
	 *
	 * This item must be first in the data structure. It'll be then casted to
	 * the epoll_handler, which contains a function pointer as the first element.
	 */
	void (*handler)(struct pcap_interface *);
	// Link back to the loop owning this pcap. For epoll handler.
	struct loop *loop;
	const char *name;
	pcap_t *pcap;
	int fd;
	size_t offset;
};

struct plugin_holder {
	/*
	 * This one is first, so we can cast the current_context back in case
	 * of error handling.
	 */
	struct context context;
	struct plugin plugin;
};

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

GEN_CALL_WRAPPER(init)
GEN_CALL_WRAPPER(finish)

struct loop {
	struct mem_pool *permanent_pool, *temp_pool;
	struct pcap_interface *pcap_interfaces;
	size_t pcap_interface_count;
	struct plugin_holder *plugins;
	size_t plugin_count;
	int epoll_fd;
	sig_atomic_t stopped; // We may be stopped from a signal, so not bool
};

// Handle one packet.
static void packet_handler(struct pcap_interface *interface, const struct pcap_pkthdr *header, const unsigned char *data) {
	(void) data;
	ulog(LOG_DEBUG_VERBOSE, "Packet of size %zu on interface %s\n", header->caplen - interface->offset, interface->name);
}

static void pcap_read(struct pcap_interface *interface) {
	ulog(LOG_DEBUG_VERBOSE, "Read on interface %s\n", interface->name);
	int result = pcap_dispatch(interface->pcap, MAX_PACKETS, (pcap_handler) packet_handler, (unsigned char *) interface);
	if (result == -1)
		die("Error reading packets from PCAP on %s (%s)\n", interface->name, pcap_geterr(interface->pcap));
	ulog(LOG_DEBUG_VERBOSE, "Handled %d packets on %s\n", result, interface->name);
}

static void epoll_register_pcap(struct loop *loop, size_t index, int op) {
	struct epoll_event event = {
		.events = EPOLLIN,
		.data = {
			.ptr = loop->pcap_interfaces + index
		}
	};
	if (epoll_ctl(loop->epoll_fd, op, loop->pcap_interfaces[index].fd, &event) == -1)
		die("Can't register PCAP fd %d of %s to epoll fd %d (%s)\n", loop->pcap_interfaces[index].fd, loop->pcap_interfaces[index].name, loop->epoll_fd, strerror(errno));
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
	return result;
}

void loop_break(struct loop *loop) {
	loop->stopped = 1;
}

void loop_run(struct loop *loop) {
	ulog(LOG_INFO, "Running the main loop\n");
	while (!loop->stopped) {
		struct epoll_event events[MAX_EVENTS];
		// TODO: Implement timeouts.
		// TODO: Support for reconfigure signal (epoll_pwait then).
		int ready = epoll_wait(loop->epoll_fd, events, MAX_EVENTS, -1);
		if (ready == -1) {
			if (errno == EINTR) {
				ulog(LOG_WARN, "epoll_wait on %d interrupted, retry\n", loop->epoll_fd);
				continue;
			}
			die("epoll_wait on %d failed: %s\n", loop->epoll_fd, strerror(errno));
		} else if (ready == 0) {
			// This is strange. We wait for 1 event idefinitelly and get 0
			ulog(LOG_WARN, "epoll_wait on %d returned 0 events\n", loop->epoll_fd);
		} else {
			for (size_t i = 0; i < (size_t) ready; i ++) {
				/*
				 * We have the event. Now, the data has the pointer to the handler
				 * as the first element. Therefore, we can cast it to the handler.
				 */
				struct epoll_handler *handler = events[i].data.ptr;
				handler->handler(events[i].data.ptr);
			}
		}
	}
}

void loop_destroy(struct loop *loop) {
	ulog(LOG_INFO, "Releasing the main loop\n");
	// Close the epoll
	int result = close(loop->epoll_fd);
	assert(result == 0);
	// Close all PCAPs
	for (size_t i = 0; i < loop->pcap_interface_count; i ++) {
		ulog(LOG_INFO, "Closing PCAP on %s\n", loop->pcap_interfaces[i].name);
		pcap_close(loop->pcap_interfaces[i].pcap);
	}
	// Remove all the plugins.
	for (size_t i = 0; i < loop->plugin_count; i ++) {
		ulog(LOG_INFO, "Removing plugin %s\n", loop->plugins[i].plugin.name);
		plugin_finish(&loop->plugins[i]);
		mem_pool_destroy(loop->plugins[i].context.permanent_pool);
	}
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

bool loop_add_pcap(struct loop *loop, const char *interface) {
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

	// Put the PCAP into the event loop.
	/*
	 * FIXME: This throws away (and leaks) the old array for the interfaces every time.
	 * This is not currently a problem, because we use single interface only and
	 * even if we used little bit more, there would be only few interfaces anyway.
	 * But it is not really clean solution.
	 */
	struct pcap_interface *interfaces = mem_pool_alloc(loop->permanent_pool, (loop->pcap_interface_count + 1) * sizeof *interfaces);
	// Copy the old interfaces (and re-register with epoll, to change the pointer)
	memcpy(interfaces, loop->pcap_interfaces, loop->pcap_interface_count * sizeof *interfaces);
	for (size_t i; i < loop->pcap_interface_count; i ++)
		epoll_register_pcap(loop, i, EPOLL_CTL_MOD);
	assert(pcap_datalink(pcap) <= DLT_PFLOG);
	interfaces[loop->pcap_interface_count ++] = (struct pcap_interface) {
		.handler = pcap_read,
		.loop = loop,
		.name = mem_pool_strdup(loop->permanent_pool, interface),
		.pcap = pcap,
		.fd = fd,
		.offset = ip_offset_table[pcap_datalink(pcap)]
	};
	loop->pcap_interfaces = interfaces;
	epoll_register_pcap(loop, loop->pcap_interface_count - 1, EPOLL_CTL_ADD);
	return true;
}

void loop_add_plugin(struct loop *loop, struct plugin *plugin) {
	ulog(LOG_INFO, "Installing plugin %s\n", plugin->name);
	// Store the plugin structure.
	/*
	 * Currently, we throw away the old array and leak little bit. This is OK for now,
	 * as we'll register just few plugins on start-up. However, once we have the ability
	 * to reconfigure at run-time and we support removing and adding the plugins again,
	 * we need to solve it somehow.
	 */
	struct plugin_holder *plugins = mem_pool_alloc(loop->permanent_pool, (loop->plugin_count + 1) * sizeof *plugins);
	memcpy(plugins, loop->plugins, loop->plugin_count * sizeof *plugins);
	struct plugin_holder *new = loop->plugins + loop->plugin_count ++;
	/*
	 * Each plugin gets its own permanent pool (since we'd delete that one with the plugin),
	 * but we can reuse the temporary pool.
	 */
	*new = (struct plugin_holder) {
		.context = {
			.permanent_pool = mem_pool_create(plugin->name),
			.temp_pool = loop->temp_pool
		},
		.plugin = *plugin
	};
	// Copy the name (it may be temporary), from the plugin's own pool
	new->plugin.name = mem_pool_strdup(new->context.permanent_pool, plugin->name);
	plugin_init(new);
}

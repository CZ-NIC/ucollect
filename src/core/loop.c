#include "loop.h"
#include "mem_pool.h"
#include "util.h"

#include <signal.h> // for sig_atomic_t
#include <assert.h>
#include <string.h> // Why is memcpy in string?
#include <errno.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <sys/epoll.h>

struct pcap_interface {
	/*
	 * This will be always set to pcap_read. Trick to make the epollhandling
	 * simpler ‒ we put this struct directly as the user data to epoll and the
	 * generic handler calls the handler found, no matter what type it is.
	 */
	void (*handler)(struct pcap_interface *);
	// Link back to the loop owning this pcap. For epoll handler.
	struct loop *loop;
	const char *name;
	pcap_t *pcap;
	int fd;
	size_t offset;
};

struct loop {
	struct mem_pool *permanent_pool;
	struct pcap_interface *pcap_interfaces;
	size_t pcap_interface_count;
	int epoll_fd;
	sig_atomic_t stopped; // We may be stopped from a signal, so not bool
};

static void pcap_read(struct pcap_interface *interface) {
	ulog(LOG_DEBUG, "Read on interface %s\n", interface->name);
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
		// TODO
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
	// TODO: Should these be configurable (run-time or compile-time?)
	int result = pcap_set_promisc(pcap, 1);
	assert(result == 0); // Can error only on code errors
	result = pcap_set_timeout(pcap, 1000); // One second
	assert(result == 0);
	pcap_set_buffer_size(pcap, 655360);
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
	// TODO: Handle the errors here. There's a list of warnings and list in the man page.
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
	// TODO: Register with epoll.
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

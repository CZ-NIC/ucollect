#include "loop.h"
#include "mem_pool.h"
#include "util.h"

#include <signal.h> // for sig_atomic_t
#include <pcap/pcap.h>
#include <assert.h>
#include <string.h> // Why is memcpy in string?

struct pcap_interface {
	const char *name;
	pcap_t *pcap;
	int fd;
	size_t offset;
};

struct loop {
	struct mem_pool *permanent_pool;
	struct pcap_interface *pcap_interfaces;
	size_t pcap_interface_count;
	sig_atomic_t stopped; // We may be stopped from a signal, so not bool
};

struct loop *loop_create() {
	ulog(LOG_INFO, "Creating a main loop\n");
	struct mem_pool *pool = mem_pool_create("Global permanent pool");
	struct loop *result = mem_pool_alloc(pool, sizeof *result);
	*result = (struct loop) {
		.permanent_pool = pool
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
	// Copy the old interfaces
	memcpy(interfaces, loop->pcap_interfaces, loop->pcap_interface_count * sizeof *interfaces);
	assert(pcap_datalink(pcap) <= DLT_PFLOG);
	interfaces[loop->pcap_interface_count ++] = (struct pcap_interface) {
		.name = mem_pool_strdup(loop->permanent_pool, interface),
		.pcap = pcap,
		.fd = fd,
		.offset = ip_offset_table[pcap_datalink(pcap)]
	};
	loop->pcap_interfaces = interfaces;
	return true;
}

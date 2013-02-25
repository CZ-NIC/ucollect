#ifndef UCOLLECT_TUNABLES_H
#define UCOLLECT_TUNABLES_H

// For the event loop
#define MAX_EVENTS 10
#define MAX_PACKETS 100
#define PCAP_TIMEOUT 100
#define PCAP_BUFFER 3276800

// For the memory pool
#define PAGE_CACHE_SIZE 20

// Uplink reconnect times
// First attempt after 2 seconds
#define RECONNECT_BASE 2000
// Maximum reconnect time of 5 minutes
#define RECONNECT_MAX (1000 * 5 * 60)
// Double the time for reconnect attempt on failure
#define RECONNECT_MULTIPLY 2

#endif

#ifndef UCOLLECT_TUNABLES_H
#define UCOLLECT_TUNABLES_H

// For the event loop
#define MAX_EVENTS 10
#define MAX_PACKETS 100
#define PCAP_TIMEOUT 100
#define PCAP_BUFFER 3276800

// How many times a plugin may fail before we give up and disable it
#define FAIL_COUNT 5

/*
 * How long to wait before interface reconfiguration attempt happens (10s).
 * This is done if the interface breaks down (like when it is turned off).
 */
#define IFACE_RECONFIGURE_TIME 10000

// We expect there should be a packet at least once in 10 minutes.
#define PCAP_WATCHDOG_TIME (10 * 1000 * 60)
// If nothing comes in 50 + a bit minutes, panic and do a full reconfigure
#define WATCHDOG_MISSED_COUNT 5

// For the memory pool
#define PAGE_CACHE_SIZE 20

// Uplink reconnect times
// First attempt after 2 seconds
#define RECONNECT_BASE 2000
// Maximum reconnect time of 5 minutes
#define RECONNECT_MAX (1000 * 5 * 60)
// Double the time for reconnect attempt on failure
#define RECONNECT_MULTIPLY 2

// How much time to wait between pings? 30s could be enough but not too much to timeout NAT
#define PING_TIMEOUT (30 * 1000)
// If so many pings are not answered, consider the link dead
#define PING_COUNT 2

// The challenge length in bytes to send to server
#define CHALLENGE_LEN 32
// Minimum time between connection attempts
#define RECONN_TIME 1000

#endif

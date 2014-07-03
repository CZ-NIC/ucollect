/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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
// The time to wait before reconnecting because of failed login
#define RECONNECT_AUTH (1000 * 60 * 10)

// How much time to wait between pings? 60s could be enough but not too much to timeout NAT
#define PING_TIMEOUT (60 * 1000)
// If so many pings are not answered, consider the link dead
#define PING_COUNT 2

// The challenge length in bytes to send to server
#define CHALLENGE_LEN 32
// Minimum time between connection attempts
#define RECONN_TIME 1000

// Time to sleep when we receive the stray read (milliseconds)
#define STRAY_READ_SLEEP 500

// How many attempts to log in before giving up and exiting?
#define LOGIN_FAILURE_LIMIT 10

#endif

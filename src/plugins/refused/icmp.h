/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

// Parsing of destination unreachable from ICMP and ICMPv6 packets

#ifndef UCOLLECT_REFUSED_ICMP_H
#define UCOLLECT_REFUSED_ICMP_H

#include <stdlib.h>
#include <stdint.h>

struct packet_info *info;

/*
 * Look into a packet and decide if it is a destination unreachable ICMP packet
 * for a TCP connection.
 *
 * If it is, return the type by the return value and provide info about the
 * connection it belongs to. The types are:
 * - 'N': Network unreachable.
 * - 'H': Host unreachable.
 * - 'P': Port unreachable.
 * - 'O': Some other reasone.
 * - 'A': Administratively prohibited.
 *
 * In case it is not such NAK packet, it returns '\0'.
 */
char nak_parse(const struct packet_info *packet, size_t *addr_len, const uint8_t **addr, uint16_t *loc_port, uint16_t *dest_port);

#endif

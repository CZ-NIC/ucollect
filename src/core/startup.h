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

/*
 * Some helper functions to start up the main process. They
 * don't do much, but repeating them is boring.
 */

#ifndef UCOLLECT_STARTUP_H
#define UCOLLECT_STARTUP_H

struct loop;
struct uplink;

// The main loop used by the process and the uplink (if any).
extern struct loop *loop;
extern struct uplink *uplink;

// Set up shutdown signals
void set_stop_signals(void);

// Free the loop and uplink, if they exist
void system_cleanup(void);

#endif

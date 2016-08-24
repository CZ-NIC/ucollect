/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2016 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "base64.h"

#include <stdbool.h>
#include <string.h>

/*
 * The code is slightly inspired by the one from libucw, but
 * rewritten from scratch to suit our needs better.
 */

/*
 * This is OK, since all the characters here are <128 and therefore
 * have the same value as signed and unsigned.
 */
const uint8_t *allowed = (const uint8_t *)
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

size_t base64_decode_inplace(uint8_t *buffer) {
	// Mapping character → index
	static uint8_t reverse[265];
	static bool init = false;
	if (!init) {
		// Mark all positions as invalid first
		memset(reverse, 0xFF, sizeof reverse);
		// Go through the allowed characters and place a value to each, so we can index by them
		for (size_t i = 0; allowed[i]; i ++)
			reverse[allowed[i]] = i;
		init = true;
	}
	// Positions in the buffer (in moves faster, so they have separate counters)
	size_t in = 0;
	size_t out = 0;
	// Count the valid input characters (we ignore invalid ones, so it may be different than in)
	size_t vin = 0;
	uint8_t val;
	while ((val = buffer[in ++])) {
		val = reverse[val];
		if (val == 0xFF)
			// Invalid character. Move to the next.
			continue;
		switch (vin ++ % 4) {
			case 0:
				buffer[out] = val << 2;
				break;
			case 1:
				buffer[out ++] |= val >> 4;
				buffer[out] = (val & 0x0F) << 4;
				break;
			case 2:
				buffer[out ++] |= val >> 2;
				buffer[out] = (val & 0x03) << 6;
				break;
			case 3:
				buffer[out ++] |= val;
				break;
		}
	}
	// NULL-terminate for convenience
	buffer[out] = '\0';
	return out;
}

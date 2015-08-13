/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "rng.h"

#include <assert.h>

struct rng_seed rng_seed_init(uint64_t seed) {
	struct rng_seed result;
	/*
	 * Since people tend to use quite small numbers and no
	 * number in the seed may be zero, we split the bits to
	 * even and odd, then interleave them to form the smaller
	 * number (we could shift them to the right one by one,
	 * but that would be more work).
	 */
	uint64_t even = seed & 0x5555555555555555LLU;
	uint64_t odd = seed & 0xAAAAAAAAAAAAAAAALLU;
	result.low = (even & 0x00000000FFFFFFFFLLU) | ((even & 0xFFFFFFFF00000000LLU) >> 31);
	result.high = (odd & 0x00000000FFFFFFFFLLU) | ((odd & 0xFFFFFFFF00000000LLU) >> 33);
	assert(result.low && result.high);
	return result;
}

uint32_t rng_get(struct rng_seed *seed) {
	seed->low = 36969 * (seed->low & 0xFFFF) + (seed->low >> 16);
	seed->high = 18000 * (seed->high & 0xFFFF) + (seed->high >> 16);
	return (seed->high << 16) + seed->low;
}

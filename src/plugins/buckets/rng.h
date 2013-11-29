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

#ifndef UCOLLECT_RNG_H
#define UCOLLECT_RNG_H

#include <stdint.h>

/*
 * The generation of random numbers is too important to be left to chance.
 *
 * We need random numbers to generate a system of perfect hashing system.
 * While we don't really need some very strong randomness, we do need
 * the random numbers generated to be the same on each client.
 *
 * We could generate them on the server and send them everywhere, but
 * that is needlessly large data. We can't use the random.h, since
 * nobody guarantees different environments to generate the same random
 * numbers with the same seed.
 *
 * Therefor we write our own (well, taken from wikipedia, see
 * https://en.wikipedia.org/wiki/Random_number_generation#Computational_methods,
 * as of 6.3.2013 and send the same seed from the server to each client.
 */

struct rng_seed {
	uint32_t low, high;
};

// Get a new seed. Returns it.
struct rng_seed rng_seed_init(uint64_t seed);

// Generate a random number and update the seed.
uint32_t rng_get(struct rng_seed *seed) __attribute__((nonnull));

#endif

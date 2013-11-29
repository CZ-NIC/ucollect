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

#ifndef UCOLLECT_BUCKET_HASH_H
#define UCOLLECT_BUCKET_HASH_H

#include <stdint.h>
#include <stddef.h>

struct mem_pool;

// Gen enough random data for these hash functions
const uint32_t *gen_hash_data(uint64_t seed_base, size_t hash_count, size_t hash_line_size, struct mem_pool *pool);

// Compute hash of given key. Provide random data for the computation.
uint32_t hash(const uint8_t *key, size_t key_size, const uint32_t *hash_data);

#endif

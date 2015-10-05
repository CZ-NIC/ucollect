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

#ifndef UCOLLECT_FLOW_FILTER_H
#define UCOLLECT_FLOW_FILTER_H

#include "../../libs/diffstore/diff_store.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct filter;
struct packet_info;
struct mem_pool;

bool filter_apply(struct mem_pool *tmp_pool, const struct filter *filter, const struct packet_info *packet) __attribute__((nonnull));
struct filter *filter_parse(struct mem_pool *pool, const uint8_t *desc, size_t size) __attribute__((nonnull));

// Decide how to react to a change on the server. Orig-version is used as an out-parameter in case of FILTER_INCREMENTAL
enum diff_store_action filter_action(struct filter *filter, const char *name, uint32_t epoch, uint32_t version, uint32_t *orig_version);
/*
 * Apply a difference to a filter of given name.
 *
 * It can use the memory pool to allocate permanent data (in the filter).
 *
 * It usually returns FILTER_NO_ACTION, which means the change was successful.
 * However, it can request a full update instead of incremental, if the epoch is different, or say FILTER_UNKNOWN if the filter is not known (or whatever other value ‒ see orig_version in filter_action).
 */
enum diff_store_action filter_diff_apply(struct mem_pool *tmp_pool, struct filter *filter, const char *name, bool full, uint32_t epoch, uint32_t from, uint32_t to, const uint8_t *diff, size_t diff_size, uint32_t *orig_version);

#endif

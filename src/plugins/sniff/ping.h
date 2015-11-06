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

#ifndef UCOLLECT_SNIFF_PING_H
#define UCOLLECT_SNIFF_PING_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

struct task_data;
struct context;
struct mem_pool;

struct task_data *start_ping(struct context *context, struct mem_pool *pool, const uint8_t *message, size_t message_size, int *output, pid_t *pid);
const uint8_t *finish_ping(struct context *context, struct task_data *data, uint8_t *output, size_t output_size, size_t *result_size, bool *ok);

#endif

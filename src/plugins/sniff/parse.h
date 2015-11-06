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

#ifndef UCOLLECT_SNIFF_PARSE_H
#define UCOLLECT_SNIFF_PARSE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

struct target;

struct task_data {
	bool input_ok;
	bool system_ok;
	size_t target_count;
	struct target *targets;
};

struct context;
struct mem_pool;

typedef bool (*task_parse_t)(struct mem_pool *task_pool, struct mem_pool *tmp_pool, struct target *target, char **args, const uint8_t **message, size_t *message_size, size_t index);

struct task_data *input_parse(struct context *context, struct mem_pool *pool, const uint8_t *message, size_t message_size, int *output, pid_t *pid, const char *program, const char *name, size_t params_per_target, size_t target_size, task_parse_t task_parse);

#endif

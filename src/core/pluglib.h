/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#ifndef UCOLLECT_PLUGLIB_H
#define UCOLLECT_PLUGLIB_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "tunable.h"

typedef void (*pluglib_function)(void);

struct pluglib_export {
	const char *name;
	pluglib_function function;
	const char *prototype;
};

struct pluglib {
	const char *name;
	size_t ref_count; // For use by the core app, do not fill in.
	size_t compat;
	size_t version;
	struct pluglib *recycler_next; // For use by the core app, do not fill in.
	struct pluglib_export **exports;
};

struct pluglib_import {
	const char *name;
	pluglib_function *function;
	const char *prototype;
};

struct pluglib_node {
	struct pluglib_node *next, *prev;
	struct pluglib *lib;
	void *handle;
	bool ready;
	uint8_t hash[CHALLENGE_LEN / 2];
};

struct pluglib_list {
	struct pluglib_node *head, *tail;
};

// Link the functions from pluglib into a plugin
bool pluglib_resolve_functions(const struct pluglib_list *libraries, struct pluglib_import **imports) __attribute__((nonnull(1)));
// Check if all the imports could be satisfied.
bool pluglib_check_functions(const struct pluglib_list *libraries, struct pluglib_import **imports) __attribute__((nonnull(1)));

#define PLUGLIB_IMPORT(NAME, RETURN, ...) static RETURN (*NAME)(__VA_ARGS__); static struct pluglib_import NAME##_import = { .name = #NAME, .function = (pluglib_function *)&NAME, .prototype = #__VA_ARGS__ "->" #RETURN }

#define PLUGLIB_EXPORT(NAME, RETURN, ...) static RETURN NAME(__VA_ARGS__); static struct pluglib_export NAME##_export = { .name = #NAME, .function = (pluglib_function)&NAME, .prototype = #__VA_ARGS__ "->" #RETURN }

#endif

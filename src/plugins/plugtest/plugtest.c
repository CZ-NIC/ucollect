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

#include "../../core/plugin.h"
#include "../../core/loop.h"
#include "../../core/context.h"

PLUGLIB_IMPORT(hello_world, void, void);

static void timeout(struct context *context, void *data __attribute__((unused)), size_t id __attribute__((unused))) {
	hello_world();
	loop_timeout_add(context->loop, 1000, context, NULL, timeout);
}

static void init(struct context *context) {
	timeout(context, NULL, 0);
}

#ifdef STATIC
struct plugin *plugin_info_plugtest(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct pluglib_import *imports[] = {
		&hello_world_import,
		NULL
	};
	static struct plugin plugin = {
		.name = "PlugTest",
		.version = 1,
		.imports = imports,
		.init_callback = init
	};
	return &plugin;
}

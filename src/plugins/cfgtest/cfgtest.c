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

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/loop.h"
#include "../../core/util.h"

static bool check(struct context *context) {
	ulog(LLOG_INFO, "Check called\n");
	const struct config_node *conf = loop_plugin_option_get(context, "test2");
	ulog(LLOG_INFO, "There are %zu options\n", conf ? conf->value_count : 0);
	if (conf) {
		for (size_t i = 0; i < conf->value_count; i ++)
			ulog(LLOG_INFO, "Val: %s\n", conf->values[i]);
	}
	conf = loop_plugin_option_get(context, "Test3");
	if (conf) {
		ulog(LLOG_ERROR, "Test3 is available\n");
		return false;
	}
	return true;
}

static void finish(struct context *context, bool activate) {
	(void)context;
	ulog(LLOG_INFO, "Finish called, activate: %d\n", (int)activate);
}

#ifdef STATIC
struct plugin *plugin_info_cfgtest(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "CfgTest",
		.config_check_callback = check,
		.config_finish_callback = finish,
		.version = 1
	};
	return &plugin;
}

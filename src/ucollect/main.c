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

#include "../core/loop.h"
#include "../core/util.h"
#include "../core/uplink.h"
#include "../core/configure.h"
#include "../core/startup.h"
#include "../core/tunable.h"
#include "../core/mem_pool.h"

#include <syslog.h>
#include <string.h>

static void dump_stats(struct context *context, void *data, size_t id) {
	(void)context;
	(void)data;
	(void)id;
	char *stats = mem_pool_stats(loop_temp_pool(loop));
	char *tok;
	while ((tok = strtok(stats, ","))) {
		stats = NULL;
		while (*tok == ' ')
			tok ++;
		ulog(LLOG_INFO, "Mempool stats: %s\n", tok);
	}
	ulog(LLOG_INFO, "Mempool stats done\n");
	loop_timeout_add(loop, STAT_DUMP_TIMEOUT, NULL, NULL, dump_stats);
}

int main(int argc, const char* argv[]) {
	(void) argc;
	openlog("ucollect", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);

	if (argv[1]) {
		ulog(LLOG_DEBUG, "Setting config dir to %s\n", argv[1]);
		config_set_dir(argv[1]);
	}
	config_set_package("ucollect");
	// Create the loop.
	loop = loop_create();

	loop_timeout_add(loop, STAT_DUMP_TIMEOUT, NULL, NULL, dump_stats);

	// Connect upstream
	uplink = uplink_create(loop);

	set_stop_signals();

	if (!load_config(loop))
		die("No configuration available\n");

	// Run until a stop signal comes.
	loop_run(loop);

	system_cleanup();
	return 0;
}

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

#ifndef UCOLLECT_PLUGIN_H
#define UCOLLECT_PLUGIN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct context;
struct packet_info;

struct config_node {
	const char **values;
	size_t value_count;
};

typedef void (*packet_callback_t)(struct context *context, const struct packet_info *info);
typedef void (*fd_callback_t)(struct context *context, int fd, void *tag);

struct plugin {
	const char *name;
	packet_callback_t packet_callback;
	void (*init_callback)(struct context *context);
	void (*finish_callback)(struct context *context);
	void (*uplink_connected_callback)(struct context *context);
	void (*uplink_disconnected_callback)(struct context *context);
	void (*uplink_data_callback)(struct context *context, const uint8_t *data, size_t length);
	fd_callback_t fd_callback;
	uint16_t version; // Protocol version (not necessarily increased after each code change in the plugin, only if it may need change on the server)
	// Called when the plugin should check configuration. Use loop_plugin_option_get to read it and return if the config is OK. Do not use yet.
	bool (*config_check_callback)(struct context *context);
	// A decision has been made if this config is globaly OK. If activate is true, start using it (you can store it in config_check or read it any time later with loop_plugin_option_get). If it is false, then return to the previous config (and loop_plugin_option_get will return the old value).
	void (*config_finish_callback)(struct context *context, bool activate);
};

#endif

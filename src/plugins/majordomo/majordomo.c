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

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/loop.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <endian.h>
#include <stdio.h>

#define CONF_FILE_DST "/tmp/ucollect_majordomo"

struct user_data {
	FILE *file;
};

static void get_string_from_raw_ip(const struct packet_info *info, int endpoint, char *output) {
	if (info->ip_protocol == 4) {
		struct in_addr addr;

		memcpy(&addr, info->addresses[endpoint], info->addr_len);

		if (inet_ntop(AF_INET, (void *)&addr, output, INET_ADDRSTRLEN) == NULL) {
			//OK, any reason why it could failed?
			strcpy(output, "FAILED");
			ulog(LLOG_DEBUG_VERBOSE, "MAJORDOMO: conversion failed\n");
		}

	} else if (info->ip_protocol == 6) {
		struct in6_addr addr;

		memcpy(&addr, info->addresses[endpoint], info->addr_len);

		if (inet_ntop(AF_INET6, (void *)&addr, output, INET6_ADDRSTRLEN) == NULL) {
			//OK, any reason why it could failed?
			strcpy(output, "FAILED");
			ulog(LLOG_DEBUG_VERBOSE, "MAJORDOMO: conversion failed\n");
		}
	}
}

void packet_handle(struct context *context, const struct packet_info *info) {
	if (info->next) {
		// It's wrapper around some other real packet. We're not interested in the envelope.
		packet_handle(context, info->next);
		return;
	}

	if (info->direction != DIR_OUT) {
		//Only outgoing packets
		return;
	}

	if (info->app_protocol != 'T' && info->app_protocol != 'U') {
		//Interested only in UDP and TCP packets
		return;
	}

	//IPv6 has longer strings, use them - don't care about few bytes overhead
	char src_str[INET6_ADDRSTRLEN];
	char dst_str[INET6_ADDRSTRLEN];

	//Get IP representation of strings
	get_string_from_raw_ip(info, END_SRC, src_str);
	get_string_from_raw_ip(info, END_DST, dst_str);

	//Get protocol string
	char *app_protocol;
	if (info->app_protocol == 'T') {
		app_protocol = "TCP";
	} else if (info->app_protocol == 'U') {
		app_protocol = "UDP";
	}

	ulog(LLOG_DEBUG_VERBOSE, "[MAJORDOMO] IPv%d %s packet from %s:%u to %s:%u - packet size = %zu; payload size = %zu\n", info->ip_protocol, app_protocol, src_str, info->ports[END_SRC], dst_str, info->ports[END_DST], info->length, info->length-info->hdr_length);
	fprintf(context->user_data->file, "%d,%s,%s,%s,%zu,%zu\n", info->ip_protocol, app_protocol, src_str, dst_str, info->length, info->length - info->hdr_length);

}

static void init(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.file = fopen(CONF_FILE_DST, "w+")
	};
}

static void destroy(struct context *context) {
	fclose(context->user_data->file);
}

#ifdef STATIC
struct plugin *plugin_info_majordomo(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Majordomo",
		.packet_callback = packet_handle,
		.init_callback = init,
		.finish_callback = destroy
	};
	return &plugin;
}

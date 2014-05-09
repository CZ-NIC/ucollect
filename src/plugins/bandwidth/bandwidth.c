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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <endian.h>
#include <stdio.h>
#include <inttypes.h>

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/loop.h"

#define WINDOW_US_LEN 5000
//#define WINDOW_US_LEN 1000000

struct user_data {
	unsigned long long int in_max;
	unsigned long long int in_sum;
	unsigned long long int out_max;
	unsigned long long int out_sum;
	unsigned long long int last_window_start;
};

static float get_speed(unsigned long long int bytes_in_window, unsigned long long int window_size) {
	//OK, try to get MB/s
	unsigned long long int windows_in_second = 1000000/window_size;
	//return (unsigned int)(bytes_in_window*windows_in_second);
	return (bytes_in_window*windows_in_second/(float)(1024*1024));
	//return (unsigned int)(bytes_in_window*8*windows_in_second/1000000);
}

static unsigned long long int reset_window_timestamp(void) {
	//struct timespec ts;
	//clock_gettime(CLOCK_MONOTONIC, &ts);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (1000000*tv.tv_sec) + (tv.tv_usec);
}

void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *d = context->user_data;
	//Filter some useless packets
	if (info->next) {
		// It's wrapper around some other real packet. We're not interested in the envelope.
		packet_handle(context, info->next);
		return;
	}

	if (info->app_protocol != 'T' && info->app_protocol != 'U') {
		//Interested only in UDP and TCP packets
		return;
	}
	//DEBUG
	//ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: WS = %llu; WE = %llu; TS = %llu\n", d->last_window_start, d->last_window_start+WINDOW_US_LEN, info->timestamp);

	//Check that the clock did not change
	if (info->timestamp < d->last_window_start) {
		//The only reasonable reaction os replace position of window and drop numbers of "broken window"
		d->last_window_start = reset_window_timestamp();
		d->in_sum = 0;
		d->out_sum = 0;
		ulog(LLOG_DEBUG_VERBOSE, "Dropping window - time changed?");
	}

	while (info->timestamp > d->last_window_start + WINDOW_US_LEN) {
		d->last_window_start += WINDOW_US_LEN;
		if (d->in_sum > d->in_max) {
			d->in_max = d->in_sum;
			ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: New download maximum achieved: %llu (%f MB/s)\n", d->in_max, get_speed(d->in_max, WINDOW_US_LEN));
		}
		if (d->out_sum > d->out_max) {
			d->out_max = d->out_sum;
			ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: New upload maximum achieved: %llu (%f MB/s)\n", d->out_max, get_speed(d->out_max, WINDOW_US_LEN));
		}
		ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: WINDOW: DOWNLOAD: %llu (%.1f MB/s)\n", d->in_sum, get_speed(d->in_sum, WINDOW_US_LEN));
		ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: WINDOW: UPLOAD: %llu (%.1f MB/s)\n", d->out_sum, get_speed(d->out_sum, WINDOW_US_LEN));
		d->in_sum = 0;
		d->out_sum = 0;
	}

	if (info->direction == DIR_IN) {
		d->in_sum += info->length;
	} else {
		d->out_sum += info->length;
	}
}


void init(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*context->user_data = (struct user_data) {
		.in_max = 0,
		.in_sum = 0,
		.out_max = 0,
		.out_sum = 0,
		.last_window_start = reset_window_timestamp()
	};
}

#ifdef STATIC
struct plugin *plugin_info_bandwidth(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Bandwidth",
		.packet_callback = packet_handle,
		.init_callback = init,
	};
	return &plugin;
}

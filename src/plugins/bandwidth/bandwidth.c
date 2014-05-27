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

#define WINDOWS_CNT 3

struct window {
	unsigned long long int len; //length of window in us
	unsigned long long int in_max;
	unsigned long long int in_sum;
	unsigned long long int out_max;
	unsigned long long int out_sum;
	unsigned long long int last_window_start;
};

struct user_data {
	struct window windows[WINDOWS_CNT];
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

	for (size_t window = 0; window < WINDOWS_CNT; window++) {
		//Check that the clock did not change
		if (info->timestamp < d->windows[window].last_window_start) {
			//The only reasonable reaction is replace position of window and drop numbers of "broken window"
			d->windows[window].last_window_start = reset_window_timestamp();
			d->windows[window].in_sum = 0;
			d->windows[window].out_sum = 0;
			ulog(LLOG_DEBUG_VERBOSE, "Dropping window - time changed?\n");
		}

		while (info->timestamp > d->windows[window].last_window_start + d->windows[window].len) {
			d->windows[window].last_window_start += d->windows[window].len;
			if (d->windows[window].in_sum > d->windows[window].in_max) {
				d->windows[window].in_max = d->windows[window].in_sum;
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: WINDOW %llu us: New download maximum achieved: %llu (%f MB/s)\n", d->windows[window].len, d->windows[window].in_max, get_speed(d->windows[window].in_max, d->windows[window].len));
			}
			if (d->windows[window].out_sum > d->windows[window].out_max) {
				d->windows[window].out_max = d->windows[window].out_sum;
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: WINDOW %llu us: New upload maximum achieved: %llu (%f MB/s)\n", d->windows[window].len, d->windows[window].out_max, get_speed(d->windows[window].out_max, d->windows[window].len));
			}
			if (d->windows[window].in_sum != 0 || d->windows[window].out_sum != 0) {
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: WINDOW %llu us: DOWNLOAD: %llu (%.1f MB/s)\tUPLOAD: %llu (%.1f MB/s)\n", d->windows[window].len, d->windows[window].in_sum, get_speed(d->windows[window].in_sum, d->windows[window].len), d->windows[window].out_sum, get_speed(d->windows[window].out_sum, d->windows[window].len));
			}
			d->windows[window].in_sum = 0;
			d->windows[window].out_sum = 0;
		}

		if (info->direction == DIR_IN) {
			d->windows[window].in_sum += info->length;
		} else {
			d->windows[window].out_sum += info->length;
		}
	}
}

void init(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	//struct user_data *d = context->user_data;

	size_t i = 0;
	unsigned long long int common_start_timestamp = reset_window_timestamp();
	context->user_data->windows[i++] = (struct window) {
		.len = 5000,
		.in_max = 0,
		.in_sum = 0,
		.out_max = 0,
		.out_sum = 0,
		.last_window_start = common_start_timestamp
	};

	context->user_data->windows[i++] = (struct window) {
		.len = 100000,
		.in_max = 0,
		.in_sum = 0,
		.out_max = 0,
		.out_sum = 0,
		.last_window_start = common_start_timestamp
	};

	context->user_data->windows[i++] = (struct window) {
		.len = 1000000,
		.in_max = 0,
		.in_sum = 0,
		.out_max = 0,
		.out_sum = 0,
		.last_window_start = common_start_timestamp
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

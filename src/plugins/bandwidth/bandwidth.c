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

#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/loop.h"

#define WINDOW_GROUPS_CNT 5

// Settings for communication protocol
#define PROTO_ITEMS_PER_WINDOW 3

// Settings for debug dumps
#define DBG_DUMP_INTERVAL 3000 //in ms
#define DBG_DUMP_FILE "/tmp/ucollect_bandwidth_dump"
#define DBG_DUMP_PREP_FILE "/tmp/.ucollect_bandwidth_dump_next"

struct frame {
	uint64_t in_sum;
	uint64_t out_sum;
};

struct window {
	uint64_t len; //length of window in us
	size_t cnt;
	uint64_t timestamp; //begin of history chain, not the current time
	size_t current_frame; //frame that presents begin of history chain, not the newer one
	uint64_t in_max;
	uint64_t out_max;
	uint64_t dbg_dump_in_max;
	uint64_t dbg_dump_out_max;
	struct frame *frames;
};

struct user_data {
	struct window windows[WINDOW_GROUPS_CNT];
	uint64_t timestamp;
	size_t dbg_dump_timeout;
};

#define SEC 1000000

// Get MB/s - for debug purposes only
static float get_speed(uint64_t bytes_in_window, uint64_t window_size) {
	float windows_in_second = SEC/(float)window_size;
	return (bytes_in_window*windows_in_second/(float)(1024*1024));
}

// Get current time in us from epoch
static uint64_t current_timestamp(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (1000000*(uint64_t)tv.tv_sec) + (uint64_t)tv.tv_usec;
}

// Get origin of history chain that is specific for window
static uint64_t delayed_timestamp(uint64_t timestamp, uint64_t window_len, size_t windows_cnt) {
	return (timestamp - window_len*windows_cnt);
}

// Window initialization - fill up static parts, allocate dynamic parts and init their values
static struct window init_window(struct mem_pool *pool, uint64_t length, size_t count, uint64_t current_time) {
	size_t mem_size = count * sizeof(struct frame);
	struct frame *frames = mem_pool_alloc(pool, mem_size);
	memset(frames, 0, mem_size);

	return (struct window) {
		.len = length,
		.cnt = count,
		.timestamp = delayed_timestamp(current_time, length, count),
		.frames = frames
	};
}

void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *d = context->user_data;

	// Make the same operation for every window
	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		// Make variables shorter
		struct window *cwindow = &(d->windows[window]);

		// Check that the clock did not change
		// If some window received packet that is older then its history drop all history and start again
		if (info->timestamp < cwindow->timestamp) {
			cwindow->timestamp = delayed_timestamp(current_timestamp(), cwindow->len, cwindow->cnt);
			memset(cwindow->frames, 0, cwindow->cnt * sizeof(struct frame));
			cwindow->current_frame = 0;
			ulog(LLOG_DEBUG_VERBOSE, "Dropping window - time changed?\n");
		}

		// "Rewind tape" to matching point
		while (info->timestamp > cwindow->timestamp + cwindow->len * cwindow->cnt) {
			if (cwindow->frames[cwindow->current_frame].in_sum > cwindow->in_max) {
				cwindow->in_max = cwindow->frames[cwindow->current_frame].in_sum;
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: PERIOD: %" PRIu64": WINDOW %" PRIu64 " us: New download maximum achieved: %" PRIu64 " (%f MB/s)\n", d->timestamp, cwindow->len, cwindow->in_max, get_speed(cwindow->in_max, cwindow->len));
			}
			if (cwindow->frames[cwindow->current_frame].out_sum > cwindow->out_max) {
				cwindow->out_max = cwindow->frames[cwindow->current_frame].out_sum;
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: PERIOD: %" PRIu64 ": WINDOW %" PRIu64 " us: New upload maximum achieved: %" PRIu64 " (%f MB/s)\n", d->timestamp, cwindow->len, cwindow->out_max, get_speed(cwindow->out_max, cwindow->len));
			}

			// Debug dump - short time maximum values
			if (cwindow->frames[cwindow->current_frame].in_sum > cwindow->dbg_dump_in_max) {
				cwindow->dbg_dump_in_max = cwindow->frames[cwindow->current_frame].in_sum;
			}
			if (cwindow->frames[cwindow->current_frame].out_sum > cwindow->dbg_dump_out_max) {
				cwindow->dbg_dump_out_max = cwindow->frames[cwindow->current_frame].out_sum;
			}

			// Move current frame pointer and update timestamp!!
			cwindow->frames[cwindow->current_frame] = (struct frame) { .in_sum = 0 };
			cwindow->timestamp += cwindow->len;
			cwindow->current_frame = (cwindow->current_frame + 1) % cwindow->cnt;
		}

		// In this point we are able to store packet in our set
		// Just find the right frame and store the value
		size_t corresponding_frame = (cwindow->current_frame + ((info->timestamp - cwindow->timestamp) / cwindow->len)) % cwindow->cnt;
		if (info->direction == DIR_IN) {
			cwindow->frames[corresponding_frame].in_sum += info->length;
		} else {
			cwindow->frames[corresponding_frame].out_sum += info->length;
		}
	}
}
static void communicate(struct context *context, const uint8_t *data, size_t length) {
	struct user_data *d = context->user_data;

	// Check validity of request
	if (length != sizeof(uint64_t))
		die("Invalid request from upstream to plugin bandwidth, size %zu\n", length);

	// Get maximum also from buffered history
	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		struct window *cwindow = &(d->windows[window]);

		for (size_t frame = 0; frame < cwindow->cnt; frame++) {
			uint64_t frame_in_sum = cwindow->frames[(cwindow->current_frame + frame) % cwindow->cnt].in_sum;
			uint64_t frame_out_sum = cwindow->frames[(cwindow->current_frame + frame) % cwindow->cnt].out_sum;

			if (frame_in_sum > cwindow->in_max) {
				cwindow->in_max = frame_in_sum;
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: PERIOD: %" PRIu64": WINDOW %" PRIu64 " us: New download maximum found in history: %" PRIu64 " (%f MB/s)\n", d->timestamp, cwindow->len, cwindow->in_max, get_speed(cwindow->in_max, cwindow->len));
			}

			if (frame_out_sum > cwindow->out_max) {
				cwindow->out_max = frame_out_sum;
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: PERIOD: %" PRIu64 ": WINDOW %" PRIu64 " us: New upload maximum found in history: %" PRIu64 " (%f MB/s)\n", d->timestamp, cwindow->len, cwindow->out_max, get_speed(cwindow->out_max, cwindow->len));
			}

		}
	}

	/*
		Prepare message.
		Message format is:
		 - timestamp
		 - for every window:
			- window length
			- in_max
			- out_max
	*/
	uint64_t *msg;
	size_t msg_size = (PROTO_ITEMS_PER_WINDOW * WINDOW_GROUPS_CNT + 1) * sizeof *msg;
	msg = mem_pool_alloc(context->temp_pool, msg_size);

	size_t fill = 0;
	msg[fill++] = htobe64(d->timestamp);
	ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: Sending timestamp %" PRIu64 "\n", d->timestamp);
	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		msg[fill++] = htobe64(d->windows[window].len);
		msg[fill++] = htobe64(d->windows[window].in_max);
		msg[fill++] = htobe64(d->windows[window].out_max);
	}

	// Send message. Don't check return code. Server ignores old data anyway.
	uplink_plugin_send_message(context, msg, msg_size);

	// Extract timestamp for the next interval
	uint64_t timestamp;
	memcpy(&timestamp, data, length);
	d->timestamp = be64toh(timestamp);
	ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: Receiving timestamp %" PRIu64 "\n", d->timestamp);

	// Reset counters
	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		struct window *cwindow = &(d->windows[window]);
		cwindow->in_max = 0;
		cwindow->out_max = 0;
	}

}

void dbg_dump(struct context *context, void *data, size_t id) {
	(void) data;
	(void) id;
	struct user_data *d = context->user_data;

	// Prepare file
	FILE *ofile = fopen(DBG_DUMP_PREP_FILE, "w+");
	if (ofile == NULL) {
		ulog(LLOG_ERROR, "BANDWIDTH: Can't open output file for debug-dump\n");
		//Schedule next dump anyway...
		context->user_data->dbg_dump_timeout = loop_timeout_add(context->loop, DBG_DUMP_INTERVAL, context, NULL, dbg_dump);
		return;
	}

	fprintf(ofile,
		"%6s%20s%20s%20s%20s%20s\n",
		"type", "win_length", "download (Bpw)", "download (MBps)", "upload (Bpw)", "upload (MBps)"
	);

	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		struct window *cwindow = &(d->windows[window]);
		fprintf(ofile,
			"%6s%20" PRIu64 "%20" PRIu64 "%20.3f%20" PRIu64 "%20.3f\n",
			"debug",
			cwindow->len,
			cwindow->dbg_dump_in_max,
			get_speed(cwindow->dbg_dump_in_max, cwindow->len),
			d->windows[window].dbg_dump_out_max,
			get_speed(cwindow->dbg_dump_out_max, cwindow->len)
		);
	}

	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		struct window *cwindow = &(d->windows[window]);
		fprintf(ofile,
			"%6s%20" PRIu64 "%20" PRIu64 "%20.3f%20" PRIu64 "%20.3f\n",
			"server",
			d->windows[window].len,
			d->windows[window].in_max,
			get_speed(cwindow->in_max, cwindow->len),
			d->windows[window].out_max,
			get_speed(cwindow->out_max, cwindow->len)
		);
	}

	fclose(ofile);

	if (rename(DBG_DUMP_PREP_FILE, DBG_DUMP_FILE) != 0) {
		ulog(LLOG_ERROR, "BANDWIDTH: rename() failed with error: %s\n", strerror(errno));
	}

	// Reset counters
	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		struct window *cwindow = &(d->windows[window]);
		cwindow->dbg_dump_in_max = 0;
		cwindow->dbg_dump_out_max = 0;
	}

	//Schedule next dump
	context->user_data->dbg_dump_timeout = loop_timeout_add(context->loop, DBG_DUMP_INTERVAL, context, NULL, dbg_dump);
}

void init(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);

	// User data initialization
	uint64_t common_start_timestamp = current_timestamp();
	context->user_data->timestamp = 0;
	context->user_data->dbg_dump_timeout = loop_timeout_add(context->loop, DBG_DUMP_INTERVAL, context, NULL, dbg_dump);

	// Windows settings
	// Parameter count should be number that windows_count*window_length is at least 1 second
	size_t i = 0;
	context->user_data->windows[i++] = init_window(context->permanent_pool, 500000, 4, common_start_timestamp);
	context->user_data->windows[i++] = init_window(context->permanent_pool, 1000000, 1, common_start_timestamp);
	context->user_data->windows[i++] = init_window(context->permanent_pool, 2000000, 1, common_start_timestamp);
	context->user_data->windows[i++] = init_window(context->permanent_pool, 5000000, 1, common_start_timestamp);
	context->user_data->windows[i++] = init_window(context->permanent_pool, 10000000, 1, common_start_timestamp);
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
		.uplink_data_callback = communicate,
		.version = 1
	};
	return &plugin;
}

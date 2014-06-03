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

#include "ping.h"
#include "fork.h"

#include "../../core/mem_pool.h"
#include "../../core/util.h"
#include "../../core/context.h"
#include "../../core/uplink.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

const char *pinger_program =
#include <sniff-ping.inc>
;

struct task_data {
	bool input_ok;
	bool system_ok;
	size_t host_count;
	size_t *ping_counts;
};

static bool host_parse(struct mem_pool *tmp_pool, char **dest, struct task_data *data, size_t host_num, const uint8_t **message, size_t *message_size) {
	size_t header = sizeof(char) + sizeof(uint8_t) + sizeof(uint16_t);
	if (*message_size < header) {
		ulog(LLOG_ERROR, "Message too short, host %zu incomplete\n", host_num);
		return false;
	}
	char proto = **message;
	uint8_t count = (*message)[sizeof proto];
	uint16_t size;
	memcpy(&size, *message + sizeof proto + sizeof count, sizeof size);
	size = ntohs(size);
	*message += header;
	*message_size -= header;
	char *host = uplink_parse_string(tmp_pool, message, message_size);
	if (!host) {
		ulog(LLOG_ERROR, "Hostname of host %zu is broken\n", host_num);
		return false;
	}
	if (proto != '4' && proto != '6' && proto != 'X') {
		ulog(LLOG_ERROR, "Unknown ping protocol %c on host %zu\n", proto, host_num);
		return false;
	}
	dest[0] = mem_pool_printf(tmp_pool, "%c", proto);
	dest[1] = mem_pool_printf(tmp_pool, "%d", count);
	dest[2] = mem_pool_printf(tmp_pool, "%d", size);
	dest[3] = host;
	data->ping_counts[host_num] = count;
	return true;
}

struct task_data *start_ping(struct context *context, struct mem_pool *pool, const uint8_t *message, size_t message_size, int *output, pid_t *pid) {
	*output = 0; // Not running yet
	struct task_data *data = mem_pool_alloc(pool, sizeof *data);
	*data = (struct task_data) {
		.input_ok = true,
		.system_ok = true
	};
	uint16_t host_count;
	if (message_size < sizeof host_count) {
		ulog(LLOG_ERROR, "Ping input broken: Message too short to contain even the number of hosts to ping (%zu bytes)\n", message_size);
		data->input_ok = false;
		return data;
	}
	memcpy(&host_count, message, sizeof host_count);
	message += sizeof host_count;
	message_size -= sizeof host_count;
	host_count = ntohs(host_count);
	char **argv = mem_pool_alloc(context->temp_pool, (6 + 4 * host_count) * sizeof *argv);
	argv[0] = "/bin/busybox";
	argv[1] = "ash";
	argv[2] = "-c";
	argv[3] = mem_pool_strdup(context->temp_pool, pinger_program);
	argv[4] = "sniff-ping";
	argv[5 + 4 * host_count] = NULL;
	data->host_count = host_count;
	data->ping_counts = mem_pool_alloc(pool, host_count * sizeof *data->ping_counts);
	for (size_t i = 0; i < host_count; ++ i)
		if (!host_parse(context->temp_pool, argv + 5 + 4 * i, data, i, &message, &message_size)) {
			data->input_ok = false;
			return data;
		}
	data->system_ok = fork_task("/bin/busybox", argv, "pinger", output, pid);
	return data;
}

static uint8_t **split(struct mem_pool *pool, uint8_t *start, uint8_t *end, uint8_t separator, size_t limit) {
	uint8_t **result = mem_pool_alloc(pool, (limit + 2) * sizeof *result), **assigned = result;
	*assigned ++ = start;
	*assigned = end;
	for (size_t i = 2; i < limit + 2; i ++)
		result[i] = NULL;
	for (uint8_t *pos = start; limit && pos < end; pos ++)
		if (*pos == separator) {
			*pos = '\0';
			*assigned ++ = pos + 1;
			*assigned = end;
			limit --;
		}
	return result;
}

const uint8_t *finish_ping(struct context *context, struct task_data *data, uint8_t *output, size_t output_size, size_t *result_size, bool *ok) {
#define FAIL(CODE, MESSAGE) do { *result_size = 1; *ok = false; ulog(LLOG_INFO, "Sending error ping response %s: %s\n", CODE, MESSAGE); return (const uint8_t *)(CODE); } while (0)
	// Basic sanity check
	if (!data->input_ok)
		FAIL("I", "Invalid input");
	if (!data->system_ok)
		FAIL("F", "Failed to run command");
	if (!output)
		FAIL("P", "The pipe burst, call the plumber");
	if (data->host_count && !output_size)
		FAIL("R", "Read error, suggest getting glasses");
	// Split to lines
	uint8_t **lines = split(context->temp_pool, output, output + output_size, '\n', data->host_count);
	if (lines[data->host_count + 1] != output + output_size || lines[data->host_count] != output + output_size)
		// Wrong number of lines
		FAIL("O", "Wrong number of lines in the output");
	// Split each line to words
	uint8_t ***words = mem_pool_alloc(context->temp_pool, data->host_count * sizeof *words);
	size_t address_size = 0, pings_total = 0;
	for (size_t i = 0; i < data->host_count; i ++) {
		size_t pc = data->ping_counts[i];
		words[i] = split(context->temp_pool, lines[i], lines[i + 1], ' ', pc + 1);
		if (words[i][pc + 2] && strcmp("END", (char *)words[i][pc + 1]) != 0)
			// Too many words (fewer is allowed)
			FAIL("O", "Too many words on a line, be brief");
		if (strcmp("END", (char *)words[i][0]) != 0) {
			// There's an IP address. Count its size. And the pings too.
			address_size += strlen((char *)words[i][0]);
			pings_total += pc;
		}
	}
	// Allocate the result and encode it.
	size_t total_size = pings_total * sizeof(uint32_t) + data->host_count * sizeof(uint32_t) + address_size, rest = total_size;
	uint8_t *result = mem_pool_alloc(context->temp_pool, total_size);
	uint8_t *pos = result;
	for (size_t i = 0; i < data->host_count; i ++) {
		// First the resolved IP address, if any.
		if (strcmp("END", (char *)words[i][0]) == 0) {
			uplink_render_string("", 0, &pos, &rest);
			continue;
		}
		uplink_render_string(words[i][0], words[i][1] - words[i][0] - 1, &pos, &rest);
		// Then the ping times. Put infinites there as not answered, then overwrite with those that were answered.
		size_t time_len = data->ping_counts[i] * sizeof(uint32_t);
		assert(time_len <= rest);
		memset(pos, 0xFF, time_len);
		size_t j = 1;
		while (words[i][j] && strcmp("END", (char *)words[i][j]) != 0) {
			unsigned index;
			double time;
			if (sscanf((char *)words[i][j], "%u:%lf", &index, &time) != 2)
				FAIL("O", "Time format error");
			if (index >= data->ping_counts[i])
				FAIL("O", "Ping index overflow");
			uint32_t encoded = htonl(time * 1000);
			memcpy(pos + index * sizeof encoded, &encoded, sizeof encoded);
			j ++;
		}
		pos += time_len;
		rest -= time_len;
	}
	assert(rest == 0);
	*ok = true;
	*result_size = total_size;
	ulog(LLOG_DEBUG, "Sending %zu bytes of ping output for %zu hosts\n", *result_size, data->host_count);
	return result;
}

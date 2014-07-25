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

#include "nat.h"
#include "fork.h"

#include "../../core/mem_pool.h"
#include "../../core/context.h"
#include "../../core/util.h"

#include <string.h>

static const char *nat_program =
#include <sniff-nat.inc>
;

struct task_data {
	bool ok;
};

struct task_data *start_nat(struct context *context, struct mem_pool *pool, const uint8_t *message, size_t message_size, int *output, pid_t *pid) {
	// We ignore the input parameters, there aren't any for this script.
	(void) message;
	(void) message_size;
	struct task_data *data = mem_pool_alloc(pool, sizeof *data);
	char **argv = mem_pool_alloc(context->temp_pool, 6 * sizeof *argv);
	argv[0] = "/bin/busybox";
	argv[1] = "ash";
	argv[2] = "-c";
	argv[3] = mem_pool_strdup(context->temp_pool, nat_program);
	argv[4] = "sniff-nat";
	argv[5] = NULL;
	data->ok = fork_task("/bin/busybox", argv, "nat", output, pid);
	return data;
}

static void parse_family(char *string, uint8_t *output, char family, char *error) {
	char *word = strtok(string, "\n");
	*output = '?';
	if (!word) {
		ulog(LLOG_ERROR, "Missing nat output for IPv%c\n", family);
		*error = 'M';
		return;
	}
	if (strcmp(word, "NONE") == 0)
		*output = '0';
	else if (strcmp(word, "NAT") == 0)
		*output = 'N';
	else if (strcmp(word, "DIRECT") == 0)
		*output = 'D';
	else {
		ulog(LLOG_ERROR, "Unknown nat output for IPv%c: '%s'\n", family, word);
		*error = 'U';
	}
}

const uint8_t *finish_nat(struct context *context, struct task_data *data, uint8_t *output, size_t output_size, size_t *result_size, bool *ok) {
	(void) output_size;
#define FAIL(CODE, MESSAGE) do { *result_size = 1; *ok = false; ulog(LLOG_INFO, "Sending error nat response %s: %s\n", CODE, MESSAGE); return (const uint8_t *)(CODE); } while (0)
	if (!data->ok)
		FAIL("S", "Failed to start");
	uint8_t *result = mem_pool_alloc(context->temp_pool, 2);
	*result_size = 2;
	char error = '\0';
	parse_family((char *)output, result, '4', &error);
	parse_family(NULL, result + 1, '6', &error);
	if (error) {
		result[0] = error;
		result[1] = '\0';
		FAIL(result, "Invalid output");
	}
	*ok = true;
	return result;
}

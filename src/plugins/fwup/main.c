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
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/uplink.h"
#include "../../core/util.h"

#include <string.h>
#include <arpa/inet.h>

enum set_state {
	SS_VALID,	// The set is valid and up to date, or a diff update would be enough. Propagate changes to the kernel.
	SS_PENDING,	// The set needs data from server, the local storage is empty. Not sending this to the kernel.
	SS_DEAD,	// Set previously available, but is no longer present in the config. It shall be deleted soon from the kernel.
	SS_NEWBORN	// Set that was just received from config and needs to be created in the kernel.
};

struct set_type {
	const char *desc;
	const char *family;
};

static const struct set_type set_types[256] = {
	['i'] = {
		.desc = "hash:ip",
		.family = "inet"
	},
	['I'] = {
		.desc = "hash:ip",
		.family = "inet6"
	},
	['b'] = {
		.desc = "hash:ip,port",
		.family = "inet"
	},
	['B'] = {
		.desc = "hash:ip,port",
		.family = "inet6"
	}
};

struct set {
	const char *name;
	enum set_state state;
	const struct set_type *type;
};

struct user_data {
	struct mem_pool *conf_pool, *standby_pool;
	bool configured;
	uint32_t config_version; // Stored in network byte order. We compare only for equality.
	size_t set_count;
	struct set *sets;
};

static void connected(struct context *context) {
	// Just ask for config
	uplink_plugin_send_message(context, "C", 1);
}

static void initialize(struct context *context) {
	struct user_data *u = context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*u = (struct user_data) {
		.conf_pool = loop_pool_create(context->loop, context, "FWUp set pool 1"),
		.standby_pool = loop_pool_create(context->loop, context, "FWUp set pool 2")
	};
	// Ask for config, if already connected (unlikely, but then, the message will get blackholed).
	connected(context);
}

struct config {
	uint32_t version;
	uint32_t set_count;
} __attribute__((packed));

static bool set_parse(struct mem_pool *pool, struct set *target, const uint8_t **data, size_t *length) {
	const char *name = uplink_parse_string(pool, data, length);
	sanity(name, "Not enough data for set name in FWUp config\n");
	sanity(length, "Not enough data for set type in FWUp config\n");
	uint8_t t = **data;
	(*data) ++;
	(*length) --;
	const struct set_type *type = &set_types[t];
	if (!type->desc) {
		ulog(LLOG_WARN, "Set %s of unknown type '%c' (%hhu), ignoring\n", name, t, t);
		return false;
	}
	*target = (struct set) {
		.name = name,
		.type = type,
		.state = SS_NEWBORN
	};
	// TODO: Init?
	return true;
}

static void config_parse(struct context *context, const uint8_t *data, size_t length) {
	struct config c;
	sanity(length >= sizeof c, "Not enough FWUp data for config, got %zu, needed %zu\n", length, sizeof c);
	memcpy(&c, data, sizeof c); // Need to copy it out, because of alignment
	struct user_data *u = context->user_data;
	if (u->config_version == c.version) {
		ulog(LLOG_DEBUG, "FWUp config up to date\n");
		// TODO Refresh the versions of sets
		return;
	}
	// Some preparations
	data += sizeof c;
	length -= sizeof c;
	// OK. We're loading the new config. First, parse which sets we have.
	size_t count = ntohl(c.set_count);
	ulog(LLOG_INFO, "FWUp config %u with %zu sets\n", (unsigned)ntohl(c.version), count);
	size_t target_count = count;
	struct mem_pool *pool = u->standby_pool;
	struct set *sets = mem_pool_alloc(pool, count * sizeof *sets);
	size_t pos = 0;
	for (size_t i = 0; i < count; i ++)
		if (set_parse(pool, &sets[pos], &data, &length))
			pos ++;
		else
			target_count --; // The set is strange, skip it.
	if (length)
		ulog(LLOG_WARN, "Extra data after FWUp filter (%zu)\n", length);
	// Drop the old config and replace by the new one
	mem_pool_reset(u->conf_pool);
	u->standby_pool = u->conf_pool;
	u->conf_pool = pool;
	u->config_version = c.version;
	u->set_count = target_count;
	u->sets = sets;
	u->configured = true;
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	sanity(length, "A zero-length message delivered to the FWUp plugin\n");
	switch (*data) {
		case 'C':
			config_parse(context, data + 1, length - 1);
			break;
		default:
			ulog(LLOG_WARN, "Unknown message opcode on FWUp: '%c' (%hhu), ignoring\n", *data, *data);
			break;
	}
}

#ifdef STATIC
#error "Fwup is not ready for static linkage. Nobody needed it."
#else
struct plugin *plugin_info(void) {
	static struct plugin plugin = {
		.name = "FWUp",
		.version = 1,
		.init_callback = initialize,
		.uplink_data_callback = communicate,
		.uplink_connected_callback = connected
	};
	return &plugin;
}

unsigned api_version() {
	return UCOLLECT_PLUGIN_API_VERSION;
}
#endif

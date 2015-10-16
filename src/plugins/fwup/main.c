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

#include "type.h"
#include "queue.h"

#define PLUGLIB_DO_IMPORT PLUGLIB_LOCAL
#include "../../libs/diffstore/diff_store.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/uplink.h"
#include "../../core/util.h"

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

enum set_state {
	SS_VALID,	// The set is valid and up to date, or a diff update would be enough. Propagate changes to the kernel.
	SS_PENDING,	// The set needs data from server, the local storage is empty. Not sending this to the kernel.
	SS_DEAD,	// Set previously available, but is no longer present in the config. It shall be deleted soon from the kernel.
	SS_DEAD_PENDING,// Like dead, but it was pending before.
	SS_COPIED,	// The set is copied into a newer storage. This one can be dropped, but leave it intact in kernel.
	SS_NEWBORN	// Set that was just received from config and needs to be created in the kernel.
};

struct set {
	const char *name;
	// When we replace the content, we do so in a temporary set we'll switch afterwards. This is the temporary name.
	const char *tmp_name;
	enum set_state state;
	const struct set_type *type;
	size_t max_size;
	struct diff_addr_store *store;
	struct context *context; // Filled in before each call on a function manipulating the set. It is needed inside the hooks.
};

struct user_data {
	struct mem_pool *conf_pool, *standby_pool;
	struct queue *queue;
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
		.standby_pool = loop_pool_create(context->loop, context, "FWUp set pool 2"),
		.queue = queue_alloc(context)
	};
	// Ask for config, if already connected (unlikely, but then, the message will get blackholed).
	connected(context);
}

struct config {
	uint32_t version;
	uint32_t set_count;
} __attribute__((packed));

static void addr_cmd(struct diff_addr_store *store, const char *cmd, const uint8_t *addr, size_t length) {
	struct set *set = store->userdata;
	enqueue(set->context, set->context->user_data->queue, mem_pool_printf(set->context->temp_pool, "%s %s %s\n", cmd, set->tmp_name ? set->tmp_name : set->name, set->type->addr2str(addr, length, set->context->temp_pool)));
}

static void add_item(struct diff_addr_store *store, const uint8_t *addr, size_t length) {
	addr_cmd(store, "add", addr, length);
}

static void remove_item(struct diff_addr_store *store, const uint8_t *addr, size_t length) {
	addr_cmd(store, "del", addr, length);
}

static void replace_start(struct diff_addr_store *store) {
	// In the replace start hook, we prepare a temporary set. All the data are going to be filled into the temporary set and then we switch the sets.
	struct set *set = store->userdata;
	assert(!set->tmp_name);
	struct mem_pool *tmp_pool = set->context->temp_pool;
	// It is OK to allocate the data from the temporary memory pool. It's lifetime is at least the length of call to the plugin communication callback, and the whole set replacement happens there.
	set->tmp_name = mem_pool_printf(tmp_pool, "%s-replace", set->name);
	enqueue(set->context, set->context->user_data->queue, mem_pool_printf(tmp_pool, "create %s %s family %s maxelem %zu\n", set->tmp_name, set->type->desc, set->type->family, set->max_size));
}

static void replace_end(struct diff_addr_store *store) {
	struct set *set = store->userdata;
	assert(set->tmp_name);
	struct mem_pool *tmp_pool = set->context->temp_pool;
	struct queue *queue = set->context->user_data->queue;
	// Swap the sets and drop the temporary one
	enqueue(set->context, queue, mem_pool_printf(tmp_pool, "swap %s %s\n", set->name, set->tmp_name));
	enqueue(set->context, queue, mem_pool_printf(tmp_pool, "destroy %s\n", set->tmp_name));
	set->tmp_name = NULL;
}

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
		.state = SS_NEWBORN,
		.max_size = uplink_parse_uint32(data, length),
		.store = diff_addr_store_init(pool, name)
	};
	target->store->add_hook = add_item;
	target->store->remove_hook = remove_item;
	target->store->replace_start_hook = replace_start;
	target->store->replace_end_hook = replace_end;
	target->store->userdata = target;
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
	// Go through the old sets and mark them as dead (so they could be resurected in the new ones)
	for (size_t i = 0; i < u->set_count; i ++)
		switch (u->sets[i].state) {
			case SS_VALID:
				u->sets[i].state = SS_DEAD;
				break;
			case SS_PENDING:
				u->sets[i].state = SS_PENDING;
				break;
			default:
				assert(0); // It's not supposed to have other states now.
				break;
		}
	// Go through the new ones and look for corresponding sets in the old config
	for (size_t i = 0; i < target_count; i ++) {
		for (size_t j = 0; j < u->set_count; j ++)
			if (strcmp(sets[i].name, u->sets[j].name) == 0 && sets[i].type == sets[j].type) {
				switch (u->sets[j].state) {
					case SS_DEAD:
						diff_addr_store_cp(sets[i].store, u->sets[j].store, context->temp_pool);
						sets[i].state = SS_VALID; // We got the data, it is valid now
						u->sets[j].state = SS_COPIED;
						break;
					case SS_DEAD_PENDING:
						// No valid data inside. So nothing to copy, really.
						sets[i].state = SS_PENDING; // It is ready in kernel
						u->sets[j].state = SS_COPIED;
						break;
					default:
						sanity(false, "Invalid set state when copying: %s %hhu\n", u->sets[j].name, (uint8_t)u->sets[j].state); // Invalid states now
						break;
				}
			}
	}
	for (size_t i = 0; i < u->set_count; i ++) {
		switch (u->sets[i].state) {
			case SS_DEAD:
			case SS_DEAD_PENDING:
				enqueue(context, u->queue, mem_pool_printf(context->temp_pool, "destroy %s\n", u->sets[i].name));
				break;
			case SS_COPIED:
				// OK, nothing to do here
				break;
			default:
				sanity(false, "Invalid set state when destroying: %s %hhu\n", u->sets[i].name, (uint8_t)u->sets[i].state); // Invalid states now
				break;
		}
	}
	for (size_t i = 0; i < target_count; i ++) {
		switch (sets[i].state) {
			case SS_NEWBORN:
				enqueue(context, u->queue, mem_pool_printf(context->temp_pool, "create %s %s family %s maxelem %zu\n", sets[i].name, sets[i].type->desc, sets[i].type->family, sets[i].max_size));
				// TODO: Ask for data
				sets[i].state = SS_PENDING;
				break;
			case SS_PENDING:
			case SS_VALID:
				// These are OK (pending already asked for data)
				break;
			default:
				sanity(false, "Invalid set state when creating: %s %hhu\n", sets[i].name, (uint8_t)sets[i].state); // Invalid states now
				break;
		}
	}
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
#error "FWUp is not ready for static linkage. Nobody needed it."
#else
struct plugin *plugin_info(void) {
	static struct pluglib_import *imports[] = {
		&diff_addr_store_init_import,
		&diff_addr_store_cp_import,
		NULL
	};
	static struct plugin plugin = {
		.name = "FWUp",
		.version = 1,
		.init_callback = initialize,
		.uplink_data_callback = communicate,
		.uplink_connected_callback = connected,
		.imports = imports
	};
	return &plugin;
}

unsigned api_version() {
	return UCOLLECT_PLUGIN_API_VERSION;
}
#endif

#include "configure.h"
#include "loop.h"
#include "util.h"
#include "mem_pool.h"

#include <uci.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

static bool load_interface(struct loop_configurator *configurator, struct uci_section *section, struct uci_context *ctx) {
	ulog(LOG_DEBUG, "Processing interface %s\n", section->e.name);
	const char *name = uci_lookup_option_string(ctx, section, "ifname");
	if (!name) {
		ulog(LOG_ERROR, "Failed to load ifname of interface %s\n", section->e.name);
		return false;
	}
	if (!loop_add_pcap(configurator, name))
		return false;
	struct uci_option *addresses = uci_lookup_option(ctx, section, "localaddr");
	if (!addresses) {
		ulog(LOG_WARN, "Failed to load local addresses (localaddr) of interface %s, assuming none are local\n", section->e.name);
		return true;
	}
	if (addresses->type != UCI_TYPE_LIST) {
		ulog(LOG_ERROR, "localaddr of interface %s isn't a list\n", section->e.name);
		return false;
	}
	struct uci_element *addr;
	uci_foreach_element(&addresses->v.list, addr) {
		ulog(LOG_DEBUG, "Adding address %s\n", addr->name);
		if (!loop_pcap_add_address(configurator, addr->name))
			return false;
	}
	return true;
}

static bool load_plugin(struct loop_configurator *configurator, struct uci_section *section, struct uci_context *ctx) {
	ulog(LOG_DEBUG, "Processing plugin %s\n", section->e.name);
	const char *libpath = uci_lookup_option_string(ctx, section, "libname");
	if (!libpath) {
		ulog(LOG_ERROR, "Failed to load libname of plugin %s\n", section->e.name);
		return false;
	}
	// TODO: Plugin configuration
	return loop_add_plugin(configurator, libpath);
}

static bool load_uplink(struct loop_configurator *configurator, struct uci_section *section, struct uci_context *ctx) {
	ulog(LOG_DEBUG, "Processing uplink %s\n", section->e.name);
	const char *name = uci_lookup_option_string(ctx, section, "name");
	const char *service = uci_lookup_option_string(ctx, section, "service");
	const char *login = uci_lookup_option_string(ctx, section, "login");
	const char *password = uci_lookup_option_string(ctx, section, "password");
	if (!name || !service || !login || !password) {
		ulog(LOG_ERROR, "Incomplete configuration of uplink\n");
		return false;
	}
	loop_uplink_configure(configurator, name, service, login, password);
	return true;
}

static bool load_package(struct loop_configurator *configurator, struct uci_context *ctx, struct uci_package *p) {
	struct uci_element *section;
	bool seen_uplink = false;
	uci_foreach_element(&p->sections, section) {
		struct uci_section *s = uci_to_section(section);
		if (strcmp(s->type, "interface") == 0) {
			if (!load_interface(configurator, s, ctx))
				return false;
		} else if (strcmp(s->type, "plugin") == 0) {
			if (!load_plugin(configurator, s, ctx))
				return false;
		} else if (strcmp(s->type, "uplink") == 0) {
			if (seen_uplink) {
				ulog(LOG_ERROR, "Multiple uplinks in configuration\n");
				return false;
			}
			seen_uplink = true;
			if (!load_uplink(configurator, s, ctx))
				return false;
		} else
			ulog(LOG_WARN, "Ignoring config section '%s' of unknown type '%s'\n", s->e.name, s->type);
	}
	if (!seen_uplink) {
		ulog(LOG_ERROR, "No uplink configuration found\n");
		return false;
	}
	return true;
}

static bool load_config_internal(struct loop_configurator *configurator, struct uci_context *ctx) {
	struct uci_package *package;
	int ok = uci_load(ctx, "ucollect", &package);
	if (ok != UCI_OK || !package) {
		ulog(LOG_ERROR, "Can't load configuration of ucollect\n");
		return false;
	}
	bool result = load_package(configurator, ctx, package);
	uci_unload(ctx, package);
	return result;
}

bool load_config(struct loop *loop) {
	struct uci_context *ctx = uci_alloc_context();
	if (!ctx) {
		ulog(LOG_ERROR, "Can't allocate UCI context\n");
		return false;
	}
	struct loop_configurator *configurator = loop_config_start(loop);
	bool result = load_config_internal(configurator, ctx);
	uci_free_context(ctx);
	if (result)
		loop_config_commit(configurator);
	else
		loop_config_abort(configurator);
	return result;
}

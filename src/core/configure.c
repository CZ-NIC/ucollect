#include "configure.h"
#include "loop.h"
#include "util.h"
#include "mem_pool.h"

#include <uci.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

static bool load_interface(struct loop_configurator *configurator, struct uci_section *section, struct uci_context *ctx) {
	ulog(LLOG_DEBUG, "Processing interface %s\n", section->e.name);
	const char *name = uci_lookup_option_string(ctx, section, "ifname");
	if (!name) {
		ulog(LLOG_ERROR, "Failed to load ifname of interface %s\n", section->e.name);
		return false;
	}
	if (!loop_add_pcap(configurator, name))
		return false;
	return true;
}

static bool load_plugin(struct loop_configurator *configurator, struct uci_section *section, struct uci_context *ctx) {
	ulog(LLOG_DEBUG, "Processing plugin %s\n", section->e.name);
	const char *libpath = uci_lookup_option_string(ctx, section, "libname");
	if (!libpath) {
		ulog(LLOG_ERROR, "Failed to load libname of plugin %s\n", section->e.name);
		return false;
	}
	// TODO: Plugin configuration
	return loop_add_plugin(configurator, libpath);
}

static bool load_uplink(struct loop_configurator *configurator, struct uci_section *section, struct uci_context *ctx) {
	ulog(LLOG_DEBUG, "Processing uplink %s\n", section->e.name);
	const char *name = uci_lookup_option_string(ctx, section, "name");
	const char *service = uci_lookup_option_string(ctx, section, "service");
#ifdef SOFt_LOGIN
	const char *login = uci_lookup_option_string(ctx, section, "login");
	const char *password = uci_lookup_option_string(ctx, section, "password");
	if (!name || !service || !login || !password) {
#else
	const char *login = NULL, *password = NULL;
	if (!name || !service) {
#endif
		ulog(LLOG_ERROR, "Incomplete configuration of uplink\n");
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
				ulog(LLOG_ERROR, "Multiple uplinks in configuration\n");
				return false;
			}
			seen_uplink = true;
			if (!load_uplink(configurator, s, ctx))
				return false;
		} else
			ulog(LLOG_WARN, "Ignoring config section '%s' of unknown type '%s'\n", s->e.name, s->type);
	}
	if (!seen_uplink) {
		ulog(LLOG_ERROR, "No uplink configuration found\n");
		return false;
	}
	return true;
}

static bool load_config_internal(struct loop_configurator *configurator, struct uci_context *ctx) {
	struct uci_package *package;
	int ok = uci_load(ctx, "ucollect", &package);
	if (ok != UCI_OK || !package) {
		ulog(LLOG_ERROR, "Can't load configuration of ucollect\n");
		return false;
	}
	bool result = load_package(configurator, ctx, package);
	uci_unload(ctx, package);
	return result;
}

static const char *config_dir;

void config_set_dir(const char *dir) {
	config_dir = dir;
}

bool load_config(struct loop *loop) {
	struct uci_context *ctx = uci_alloc_context();
	if (!ctx) {
		ulog(LLOG_ERROR, "Can't allocate UCI context\n");
		return false;
	}
	if (config_dir)
		if (uci_set_confdir(ctx, config_dir) != UCI_OK) {
			ulog(LLOG_ERROR, "Can't set configuration directory to %s\n", config_dir);
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

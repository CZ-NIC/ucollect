#ifndef UCOLLECT_LOADER_H
#define UCOLLECT_LOADER_H

struct plugin;

/*
 * Does the low-level loading of plugin libraries. It only asks the plugin
 * to provide the information in struct plugin, does not initialize it.
 *
 * Call it with the library name to load.
 */

void *plugin_load(const char *libname, struct plugin *target);
void plugin_unload(void *plugin);

#endif

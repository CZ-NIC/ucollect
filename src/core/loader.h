#ifndef UCOLLECT_LOADER_H
#define UCOLLECT_LOADER_H

#include <stdint.h>

struct plugin;

/*
 * Does the low-level loading of plugin libraries. It only asks the plugin
 * to provide the information in struct plugin, does not initialize it.
 *
 * Call it with the library name to load.
 */

void *plugin_load(const char *libname, struct plugin *target, uint8_t *hash);
void plugin_unload(void *plugin);

#endif

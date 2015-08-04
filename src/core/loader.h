/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#ifndef UCOLLECT_LOADER_H
#define UCOLLECT_LOADER_H

#include <stdint.h>

struct plugin;
struct pluglib;

/*
 * Does the low-level loading of plugin libraries. It only asks the plugin
 * to provide the information in struct plugin, does not initialize it.
 *
 * Call it with the library name to load.
 */

void *plugin_load(const char *libname, struct plugin *target, uint8_t *hash) __attribute__((nonnull)) __attribute__((malloc));
void *pluglib_load(const char *libname, struct pluglib *target, uint8_t *hash) __attribute__((nonnull)) __attribute__((malloc));
// Used both for plugins and pluglibs
void plugin_unload(void *plugin) __attribute__((nonnull));

#endif

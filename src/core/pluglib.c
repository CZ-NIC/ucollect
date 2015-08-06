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

#include "pluglib.h"
#define LIST_WANT_LFOR
#include "pluglib_list.h"

#include "util.h"

#include <string.h>

static bool pluglib_resolve_functions_internal(const struct pluglib_list *libraries, struct pluglib_import *imports, bool link) {
	if (!imports)
		return true; // No imports, all satisfied
	for (; imports->name; imports ++) {
		bool found = false;
		LFOR(pluglib_list, lib, libraries) {
			if (!lib->lib->exports) // Empty library ‒ useless, but valid
				continue;
			for (const struct pluglib_export *export = lib->lib->exports; !found && export->name; export ++) {
				if (strcmp(export->name, imports->name) == 0) {
					// A candidate. Check the prototype.
					if (!export->prototype || // There's no prototype available
							!imports->prototype || // Any prototype goes
							strcmp(export->prototype, imports->prototype) == 0) { // Prototype matches
						found = true;
						if (link) {
							*imports->function = export->function;
							ulog(LLOG_DEBUG, "Linking function %s\n", export->name);
						}
						break;
					} else {
						if (link)
							ulog(LLOG_WARN, "Prototype for function %s does not match (%s vs %s)\n", export->name, export->prototype, imports->prototype);
					}
				}
			}
		}
		ulog(LLOG_ERROR, "Couldn't find function %s\n", imports->name);
		return false;
	}
	return true;
}

bool pluglib_resolve_functions(const struct pluglib_list *libraries, struct pluglib_import *imports) {
	return pluglib_resolve_functions_internal(libraries, imports, true);
}

bool pluglib_check_functions(const struct pluglib_list *libraries, struct pluglib_import *imports) {
	return pluglib_resolve_functions_internal(libraries, imports, false);
}

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

/*
 * This header helps manipulating with the custom "linker" we have for pluglibs.
 * It allows for defining the needed structures and functions.
 *
 * In the pluglib, you create a header file with PLUGLIB_FUNC() macros. Inclusion
 * of this file precedes the macros.
 *
 * Define PLUGLIB_DO_EXPORT in the pluglib's implementation and then include the
 * header file. It'll create the function headers and bunch of function_name_export
 * variables which can be linked from the pluglib description.
 *
 * Similarly, define PLUGLIB_DO_IMPORT in the plugin that uses the functions to one
 * of the values in pluglib.h and include the header.
 *
 * You can include the header without any of these PLUGLIB_DO_* macros, but you get
 * only the other stuff that is not linked by the "linker".
 */

// Cleanup, drop macros created by previous inclusion of the header.
#ifdef PLUGLIB_IMPORT
#undef PLUGLIB_IMPORT
#undef PLUGLIB_EXPORT
#undef PLUGLIB_FUNC
#endif

/*
 * WARNING:
 * Macro magic ahead. While it is explained, know what you're doing when you edit it.
 *
 * The basic principle here is, the includer of the header file specifies what
 * should and should not be imported/exported and how. According to that, macros
 * PLUGLIB_IMPORT and PLUGLIB_EXPORT are created. They are either doing the
 * import/export or they are empty (so they can be called, but generate no code).
 *
 * The PLUGLIB_FUNC then calls both these macros.
 */

// The import macro. It distinguishes by the value of PLUGLIB_DO_IMPORT
#ifdef PLUGLIB_DO_IMPORT
#if PLUGLIB_DO_IMPORT == PLUGLIB_FUNCTIONS
#define PLUGLIB_IMPORT(NAME, RETURN, ...) extern RETURN (*NAME)(__VA_ARGS__);
#elif PLUGLIB_DO_IMPORT == PLUGLIB_PUBLIC
#define PLUGLIB_IMPORT(NAME, RETURN, ...) RETURN (*NAME)(__VA_ARGS__); static struct pluglib_import NAME##_import = { .name = #NAME, .function = (pluglib_function *)&NAME, .prototype = #__VA_ARGS__ "->" #RETURN };
#else
#define PLUGLIB_IMPORT(NAME, RETURN, ...) static RETURN (*NAME)(__VA_ARGS__); static struct pluglib_import NAME##_import = { .name = #NAME, .function = (pluglib_function *)&NAME, .prototype = #__VA_ARGS__ "->" #RETURN };
#endif
#undef PLUGLIB_DO_IMPORT
#else
#define PLUGLIB_IMPORT(...)
#endif

// The export stuff. Currently only on/off.
#ifdef PLUGLIB_DO_EXPORT
#define PLUGLIB_EXPORT(NAME, RETURN, ...) static RETURN NAME(__VA_ARGS__); static struct pluglib_export NAME##_export = { .name = #NAME, .function = (pluglib_function)&NAME, .prototype = #__VA_ARGS__ "->" #RETURN };
#else
#define PLUGLIB_EXPORT(...)
#endif

// Perform both possible import and possible export.
#define PLUGLIB_FUNC(...) PLUGLIB_IMPORT(__VA_ARGS__) PLUGLIB_EXPORT(__VA_ARGS__)

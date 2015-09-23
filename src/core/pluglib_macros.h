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

#ifdef PLUGLIB_IMPORT
#undef PLUGLIB_IMPORT
#undef PLUGLIB_EXPORT
#undef PLUGLIB_FUNC
#endif

#ifdef PLUGLIB_DO_IMPORT
#if PLUGLIB_DO_IMPORT == PLUGLIB_FUNCTIONS
#define PLUGLIB_IMPORT(NAME, RETURN, ...) extern RETURN (*NAME)(__VA_ARGS__);
#elif PLUGLIB_DO_IMPORT == PLUGLIB_STRUCTS
#define PLUGLIB_IMPORT(NAME, RETURN, ...) RETURN (*NAME)(__VA_ARGS__); static struct pluglib_import NAME##_import = { .name = #NAME, .function = (pluglib_function *)&NAME, .prototype = #__VA_ARGS__ "->" #RETURN };
#else
#define PLUGLIB_IMPORT(NAME, RETURN, ...) static RETURN (*NAME)(__VA_ARGS__); static struct pluglib_import NAME##_import = { .name = #NAME, .function = (pluglib_function *)&NAME, .prototype = #__VA_ARGS__ "->" #RETURN };
#endif
#undef PLUGLIB_DO_IMPORT
#else
#define PLUGLIB_IMPORT(...)
#endif

#ifdef PLUGLIB_DO_EXPORT
#define PLUGLIB_EXPORT(NAME, RETURN, ...) static RETURN NAME(__VA_ARGS__); static struct pluglib_export NAME##_export = { .name = #NAME, .function = (pluglib_function)&NAME, .prototype = #__VA_ARGS__ "->" #RETURN };
#else
#define PLUGLIB_EXPORT(...)
#endif

#define PLUGLIB_FUNC(...) PLUGLIB_IMPORT(__VA_ARGS__) PLUGLIB_EXPORT(__VA_ARGS__)

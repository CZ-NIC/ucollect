/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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
 * This header is little bit special in that it generates new code.
 * You define bunch of defines and macros and include the header.
 * The header introduces bunch of functions and undefines the macros.
 *
 * The header doesn't have the usual #ifndef guard, since it is expected
 * to include multiple times, with different defines.
 *
 * This is somewhat similar to C++ templates (but a way more powerful and
 * lightweight, and should produce more readable errors, though the code
 * is less convenient to read and it needs to be instantiated explicitly).
 *
 * This one contains the recycler - a place where objects can be put when
 * unused and recycled when needed.
 *
 * The definitions are:
 * - RECYCLER_NODE: The type of the object.
 * - RECYCLER_BASE: The object holding the recycler.
 * - RECYCLER_HEAD: Variable inside RECYCLER_BASE holding pointer to
 *   RECYCLER_NODE. Defaults to 'head'.
 * - RECYCLER_NEXT: Variable inside RECYCLER_NODE holding pointer to
 *   another RECYCLER_NODE. Defaults to next.
 * - RECYCLER_NAME(X): Macro returning name of functions provided part
 *   of the name. Could be something like prefix_##X.
 */

#include "mem_pool.h"

// Check all needed defines are there
#ifndef RECYCLER_NODE
#error "RECYCLER_NODE not defined"
#endif
#ifndef RECYCLER_BASE
#error "RECYCLER_BASE not defined"
#endif
#ifndef RECYCLER_NAME
#error "RECYCLER_NAME not defined"
#endif

// Define defaults, if not provided
#ifndef RECYCLER_HEAD
#define RECYCLER_HEAD head
#endif
#ifndef RECYCLER_NEXT
#define RECYCLER_NEXT next
#endif

/*
 * Get an object. Either an unused one, or allocate a new one from memory
 * pool.
 */
static RECYCLER_NODE *RECYCLER_NAME(get)(RECYCLER_BASE *base, struct mem_pool *pool) {
	if (base->RECYCLER_HEAD) {
		RECYCLER_NODE *result = base->RECYCLER_HEAD;
		base->RECYCLER_HEAD = result->RECYCLER_NEXT;
		return result;
	} else {
		return mem_pool_alloc(pool, sizeof(RECYCLER_NODE));
	}
}

/*
 * Release an object and put it to the recycler. It may be returned by get in future.
 */
static void RECYCLER_NAME(release)(RECYCLER_BASE *base, RECYCLER_NODE *object) {
	object->RECYCLER_NEXT = base->RECYCLER_HEAD;
	base->RECYCLER_HEAD = object;
}

#undef RECYCLER_NODE
#undef RECYCLER_BASE
#undef RECYCLER_HEAD
#undef RECYCLER_NEXT
#undef RECYCLER_NAME

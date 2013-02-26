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
 * is less convenient to read and it needs to be instantiated explicitly.
 *
 * This one contains the linked lists utilities.
 *
 * The definitions are:
 * - LIST_NODE Data type used as one node of the list.
 * - LIST_BASE Data type of the whole list
 * - LIST_HEAD Name of element in the LIST_BASE holding the first element.
 *   Defaults to "head" if not specified.
 * - LIST_TAIL Similar, just the last one. Defaults to "tail".
 * - LIST_NEXT The pointer to next node in LIST_NODE. Defaults to "next".
 * - LIST_NAME(X) Macro that generates name of identifier. The X will be
 *   given as part of the identifier.
 *
 * - LIST_WANT_APPEND_POOL Generate the LIST_NAME(append_pool) function
 */

// Check all needed defines are there
#ifndef LIST_NODE
#error "LIST_NODE not defined"
#endif
#ifndef LIST_BASE
#error "LIST_BASE not defined"
#endif
#ifndef LIST_NAME
#error "LIST_NAME not defined"
#endif

// Define defaults, if not provided
#ifndef LIST_HEAD
#define LIST_HEAD head
#endif
#ifndef LIST_TAIL
#define LIST_TAIL tail
#endif
#ifndef LIST_NEXT
#define LIST_NEXT next
#endif

// Functions
#ifdef LIST_WANT_APPEND_POOL
static LIST_NODE *LIST_NAME(append_pool)(LIST_BASE *list, struct mem_pool *pool) {
	LIST_NODE *new = mem_pool_alloc(pool, sizeof *new);
	new->LIST_NEXT = NULL;
	if (list->LIST_TAIL)
		list->LIST_TAIL->LIST_NEXT = new;
	list->LIST_TAIL = new;
	if (!list->LIST_HEAD)
		list->LIST_HEAD = new;
	return new;
}
#endif

// Clean up the defines
#undef LIST_NODE
#undef LIST_BASE
#undef LIST_HEAD
#undef LIST_TAIL
#undef LIST_NEXT
#undef LIST_NAME
#undef LIST_WANT_APPEND_POOL

#ifndef LFOR
#define LFOR(TYPE, VARIABLE, LIST) for (TYPE *VARIABLE = LIST.head; VARIABLE; VARIABLE = VARIABLE->next)
#endif

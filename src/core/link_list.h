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
 * - LIST_PREV If specified, the linked list is double-linked and this
 *   points to the previous item in it.
 * - LIST_COUNT The count variable. It is optional, but if set, the
 *   functions keep it up to date.
 * - LIST_NAME(X) A name-generating macro. It should be prefix_##X, where
 *   prefix will be something you'd like the list functions to start with.
 *
 * - LIST_WANT_APPEND_POOL Generate the LIST_NAME(append_pool) function
 * - LIST_WANT_INSERT_AFTER Generate the LIST_NAME(insert_after) function
 * - LIST_WANT_LFOR Make sure the LFOR macro works for this list
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

#if defined(LIST_WANT_APPEND_POOL) && (!defined(LIST_WANT_INSERT_AFTER))
#define LIST_WANT_INSERT_AFTER
#endif

#ifdef LIST_WANT_INSERT_AFTER
/*
 * Add the node to the list, positioned after the node 'after'. The 'after' node
 * may be NULL, in which case the item is prepended to the list. A non-null after
 * must be from the given list.
 */
static void LIST_NAME(insert_after)(LIST_BASE *list, LIST_NODE *node, LIST_NODE *after) {
	if (after) {
#ifdef LIST_PREV
		node->LIST_PREV = after;
		if (after->LIST_NEXT)
			after->LIST_NEXT->LIST_PREV = node;
#endif
		node->LIST_NEXT = after->LIST_NEXT;
		after->LIST_NEXT = node;
	} else {
#ifdef LIST_PREV
		node->LIST_PREV = NULL;
		if (list->LIST_HEAD)
			list->LIST_HEAD->LIST_PREV = node;
#endif
		node->LIST_NEXT = list->LIST_HEAD;
		list->LIST_HEAD = node;
	}
	if (list->LIST_TAIL == after)
		list->LIST_TAIL = node;
#ifdef LIST_COUNT
	list->LIST_COUNT ++;
#endif
}
#endif

// Functions
#ifdef LIST_WANT_APPEND_POOL
static LIST_NODE *LIST_NAME(append_pool)(LIST_BASE *list, struct mem_pool *pool) {
	LIST_NODE *new = mem_pool_alloc(pool, sizeof *new);
	LIST_NAME(insert_after)(list, new, list->LIST_TAIL);
	return new;
}
#endif

#ifdef LIST_WANT_LFOR
static LIST_NODE *LIST_NAME(get_head)(const LIST_BASE *list) {
	return list->LIST_HEAD;
}

static LIST_NODE *LIST_NAME(get_next)(const LIST_NODE *node) {
	return node->LIST_NEXT;
}

typedef LIST_NODE LIST_NAME(node_t);
#endif

// Clean up the defines
#undef LIST_NODE
#undef LIST_BASE
#undef LIST_HEAD
#undef LIST_TAIL
#undef LIST_NEXT
#undef LIST_NAME
#undef LIST_COUNT
#undef LIST_PREFIX
#undef LIST_PREV
#undef LIST_WANT_APPEND_POOL
#undef LIST_WANT_INSERT_AFTER

#ifdef LIST_WANT_LFOR
#ifndef LFOR
#define LFOR(TYPE, VARIABLE, LIST) for (TYPE##_node_t *VARIABLE = TYPE##_get_head((LIST)); VARIABLE; VARIABLE = TYPE##_get_next(VARIABLE))
#endif
#undef LIST_WANT_LFOR
#endif

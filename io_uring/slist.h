#ifndef INTERNAL_IO_SLIST_H
#define INTERNAL_IO_SLIST_H

#include <linux/io_uring_types.h>

/**
 * iterate over each node in a wq_list
 */
#define __wq_list_for_each(pos, head)				\
	for (pos = (head)->first; pos; pos = (pos)->next)

/**
 * iterate over a wq_list while keeping track of the previous node
 */
#define wq_list_for_each(pos, prv, head)			\
	for (pos = (head)->first, prv = NULL; pos; prv = pos, pos = (pos)->next)

/**
 * resume iteration from a node in a wq_list, keeping previous node
 */
#define wq_list_for_each_resume(pos, prv)			\
	for (; pos; prv = pos, pos = (pos)->next)

/**
 * check if a wq_list is empty
 */
#define wq_list_empty(list)	(READ_ONCE((list)->first) == NULL)

/**
 * initialize a wq_list to an empty state
 */
#define INIT_WQ_LIST(list)	do {				\
	(list)->first = NULL;					\
} while (0)

/**
 * insert a node after a given position in the wq_list
 */
static inline void wq_list_add_after(struct io_wq_work_node *node,
				     struct io_wq_work_node *pos,
				     struct io_wq_work_list *list)
{
	struct io_wq_work_node *next = pos->next;

	pos->next = node;
	node->next = next;
	if (!next)
		list->last = node;
}

/**
 * add a node at the end of the wq_list
 */
static inline void wq_list_add_tail(struct io_wq_work_node *node,
				    struct io_wq_work_list *list)
{
	node->next = NULL;
	if (!list->first) {
		list->last = node;
		WRITE_ONCE(list->first, node);
	} else {
		list->last->next = node;
		list->last = node;
	}
}

/**
 * add a node at the beginning of the wq_list
 */
static inline void wq_list_add_head(struct io_wq_work_node *node,
				    struct io_wq_work_list *list)
{
	node->next = list->first;
	if (!node->next)
		list->last = node;
	WRITE_ONCE(list->first, node);
}

/**
 * remove a node (or range) from the wq_list
 */
static inline void wq_list_cut(struct io_wq_work_list *list,
			       struct io_wq_work_node *last,
			       struct io_wq_work_node *prev)
{
	/* first in the list, if prev==NULL */
	if (!prev)
		WRITE_ONCE(list->first, last->next);
	else
		prev->next = last->next;

	if (last == list->last)
		list->last = prev;
	last->next = NULL;
}

/**
 * splice list content into another node's next pointer
 * and clear the original list
 */
static inline void __wq_list_splice(struct io_wq_work_list *list,
				    struct io_wq_work_node *to)
{
	list->last->next = to->next;
	to->next = list->first;
	INIT_WQ_LIST(list);
}

/**
 * conditionally splice non-empty list into another node
 */
static inline bool wq_list_splice(struct io_wq_work_list *list,
				  struct io_wq_work_node *to)
{
	if (!wq_list_empty(list)) {
		__wq_list_splice(list, to);
		return true;
	}
	return false;
}

/**
 * push a node onto a stack (LIFO) using io_wq_work_node pointer
 */
static inline void wq_stack_add_head(struct io_wq_work_node *node,
				     struct io_wq_work_node *stack)
{
	node->next = stack->next;
	stack->next = node;
}

/**
 * remove a node from the wq_list by reconnecting the previous node
 */
static inline void wq_list_del(struct io_wq_work_list *list,
			       struct io_wq_work_node *node,
			       struct io_wq_work_node *prev)
{
	wq_list_cut(list, node, prev);
}

/**
 * extract and return the top node from a stack
 */
static inline
struct io_wq_work_node *wq_stack_extract(struct io_wq_work_node *stack)
{
	struct io_wq_work_node *node = stack->next;

	stack->next = node->next;
	return node;
}

/**
 * return the next work item in the io_wq_work list
 */
static inline struct io_wq_work *wq_next_work(struct io_wq_work *work)
{
	if (!work->list.next)
		return NULL;

	return container_of(work->list.next, struct io_wq_work, list);
}

#endif // INTERNAL_IO_SLIST_H

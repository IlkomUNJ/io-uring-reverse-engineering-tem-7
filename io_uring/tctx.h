// SPDX-License-Identifier: GPL-2.0

struct io_tctx_node {
	struct list_head	ctx_node;
	struct task_struct	*task;
	struct io_ring_ctx	*ctx;
};

/**
* allocate io_uring context data for a specific task
*/
int io_uring_alloc_task_context(struct task_struct *task,
				struct io_ring_ctx *ctx);

/**
* remove task context node from the global table by index
*/
void io_uring_del_tctx_node(unsigned long index);

/**
* add task context node to the current task from non-submit path
*/
int __io_uring_add_tctx_node(struct io_ring_ctx *ctx);

/**
* add task context node during io_uring submission
*/
int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx);

/**
* clean up all per-task io_uring context data
*/
void io_uring_clean_tctx(struct io_uring_task *tctx);

/**
* unregister all ring file descriptors associated with this context
*/
void io_uring_unreg_ringfd(void);

/**
* register ring file descriptors for a given context
*/
int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg,
		       unsigned nr_args);

/**
* unregister specified ring file descriptors for a given context
*/
int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg,
			 unsigned nr_args);

/*
 * Note that this task has used io_uring. We use it for cancelation purposes.
 */
static inline int io_uring_add_tctx_node(struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx = current->io_uring;

	if (likely(tctx && tctx->last == ctx))
		return 0;

	return __io_uring_add_tctx_node_from_submit(ctx);
}

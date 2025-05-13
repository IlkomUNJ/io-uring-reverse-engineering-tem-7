// SPDX-License-Identifier: GPL-2.0

#include "cancel.h"

int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * prepare futexv wait operation from submission queue entry
 */
int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * perform wait operation on a futex address
 */
int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags);
/**
 * perform wait operation on multiple futex addresses
 */
int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags);
/**
 * wake one or more waiters waiting on a futex address
 */
int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags);

#if defined(CONFIG_FUTEX)
int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		    unsigned int issue_flags);
bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			 bool cancel_all);
/**
 * initialize futex memory cache for io_uring context
 */
bool io_futex_cache_init(struct io_ring_ctx *ctx);
/**
 * free futex memory cache associated with io_uring context
 */
void io_futex_cache_free(struct io_ring_ctx *ctx);
#else
static inline int io_futex_cancel(struct io_ring_ctx *ctx,
				  struct io_cancel_data *cd,
				  unsigned int issue_flags)
{
	return 0;
}
static inline bool io_futex_remove_all(struct io_ring_ctx *ctx,
				       struct io_uring_task *tctx, bool cancel_all)
{
	return false;
}
static inline bool io_futex_cache_init(struct io_ring_ctx *ctx)
{
	return false;
}
static inline void io_futex_cache_free(struct io_ring_ctx *ctx)
{
}
#endif

// SPDX-License-Identifier: GPL-2.0

struct io_timeout_data {
	struct io_kiocb			*req;
	struct hrtimer			timer;
	struct timespec64		ts;
	enum hrtimer_mode		mode;
	u32				flags;
};

/**
 * disarm the linked timeout request from a main request
 */
struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req,
					    struct io_kiocb *link);

static inline struct io_kiocb *io_disarm_linked_timeout(struct io_kiocb *req)
{
	struct io_kiocb *link = req->link;

	if (link && link->opcode == IORING_OP_LINK_TIMEOUT)
		return __io_disarm_linked_timeout(req, link);

	return NULL;
}

/**
 * flush all pending timeouts from the ring context
 */
__cold void io_flush_timeouts(struct io_ring_ctx *ctx);

struct io_cancel_data;

/**
 * cancel a timeout request using cancellation data
 */
int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);

/**
 * cancel all or specific task's timeouts from context
 */
__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			     bool cancel_all);

/**
 * queue a timeout request that is linked to another request
 */
void io_queue_linked_timeout(struct io_kiocb *req);

/**
 * disarm the next linked timeout from a request
 */
void io_disarm_next(struct io_kiocb *req);

/**
 * prepare a timeout request from submission queue entry
 */
int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * prepare a linked timeout request from submission queue entry
 */
int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * start a timeout using high-resolution timer
 */
int io_timeout(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare to remove an active timeout request
 */
int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * remove an active timeout request from the context
 */
int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags);

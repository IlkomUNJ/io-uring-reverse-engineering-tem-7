// SPDX-License-Identifier: GPL-2.0

#include "../kernel/exit.h"

struct io_waitid_async {
	struct io_kiocb *req;
	struct wait_opts wo;
};

/**
 * prepare a waitid request from sqe input
 */
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * perform the waitid system call operation
 */
int io_waitid(struct io_kiocb *req, unsigned int issue_flags);

/**
 * cancel an active waitid request based on cancel data
 */
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags);

/**
 * remove all waitid requests for a context or specific task
 */
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  bool cancel_all);

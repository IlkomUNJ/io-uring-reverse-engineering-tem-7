// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>

struct io_async_cmd {
	struct io_uring_cmd_data	data;
	struct iou_vec			vec;
	struct io_uring_sqe		sqes[2];
};

/**
 * execute a uring command request
 */
int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare a uring command request from sqe
 */
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * clean up any resources used by the uring command
 */
void io_uring_cmd_cleanup(struct io_kiocb *req);

/**
 * attempt to cancel uring command(s) based on context and task
 */
bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx,
				   struct io_uring_task *tctx, bool cancel_all);

/**
 * free memory associated with a cached uring command entry
 */
void io_cmd_cache_free(const void *entry);

/**
 * import user-provided iovec into a fixed vector for uring command
 */
int io_uring_cmd_import_fixed_vec(struct io_uring_cmd *ioucmd,
				  const struct iovec __user *uvec,
				  size_t uvec_segs,
				  int ddir, struct iov_iter *iter,
				  unsigned issue_flags);

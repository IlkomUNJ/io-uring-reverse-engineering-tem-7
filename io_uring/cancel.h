// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_CANCEL_H
#define IORING_CANCEL_H

#include <linux/io_uring_types.h>

struct io_cancel_data {
	struct io_ring_ctx *ctx;
	union {
		u64 data;
		struct file *file;
	};
	u8 opcode;
	u32 flags;
	int seq;
};

/**
 * prepare cancellation request from submission queue entry
 */
int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * execute asynchronous cancellation of pending requests
 */
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);

int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned int issue_flags);

/**
 * perform synchronous cancellation of request from userspace
 */
int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);
/**
 * determine if a request matches the given cancellation data
 */
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);

bool io_cancel_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  struct hlist_head *list, bool cancel_all,
/**
 * remove all cancellable requests based on given criteria
 */
			  bool (*cancel)(struct io_kiocb *));

int io_cancel_remove(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags, struct hlist_head *list,
/**
 * check whether a given request should be cancelled
 */
		     bool (*cancel)(struct io_kiocb *));

static inline bool io_cancel_match_sequence(struct io_kiocb *req, int sequence)
{
	if (req->cancel_seq_set && sequence == req->work.cancel_seq)
		return true;

	req->cancel_seq_set = true;
	req->work.cancel_seq = sequence;
	return false;
}

#endif

// SPDX-License-Identifier: GPL-2.0

int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * submit a no-op request that completes immediately without performing any action
 */
int io_nop(struct io_kiocb *req, unsigned int issue_flags);

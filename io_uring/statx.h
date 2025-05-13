// SPDX-License-Identifier: GPL-2.0

/**
* prepare statx request with parameters from the submission queue entry
*/
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
* execute a non-blocking statx syscall and handle the result
*/
int io_statx(struct io_kiocb *req, unsigned int issue_flags);

/**
* clean up resources allocated during the statx request lifecycle
*/
void io_statx_cleanup(struct io_kiocb *req);

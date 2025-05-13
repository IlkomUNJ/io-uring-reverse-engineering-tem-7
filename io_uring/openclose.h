// SPDX-License-Identifier: GPL-2.0

/**
 * close a file descriptor at a fixed offset in the fixed file table
 */
 int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags,
	unsigned int offset);

/**
* prepare an openat request from submission queue entry
*/
int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
* submit an openat request through io_uring
*/
int io_openat(struct io_kiocb *req, unsigned int issue_flags);

/**
* release resources used during openat preparation
*/
void io_open_cleanup(struct io_kiocb *req);

/**
* prepare an openat2 request with extended arguments
*/
int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
* submit an openat2 request through io_uring
*/
int io_openat2(struct io_kiocb *req, unsigned int issue_flags);

/**
* prepare a close request from submission queue entry
*/
int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
* submit a close request to close a file descriptor
*/
int io_close(struct io_kiocb *req, unsigned int issue_flags);

/**
* prepare request to install a file descriptor in fixed slot
*/
int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
* submit a request to install a file descriptor into fixed table
*/
int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags);

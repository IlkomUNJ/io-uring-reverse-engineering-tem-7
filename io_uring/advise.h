// SPDX-License-Identifier: GPL-2.0

int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * execute madvise advice on memory range via io_uring interface
 */
int io_madvise(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare fadvise parameters based on submission queue entry
 */
int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * execute posix_fadvise hint asynchronously through io_uring
 */
int io_fadvise(struct io_kiocb *req, unsigned int issue_flags);

// SPDX-License-Identifier: GPL-2.0

/**
 * prepare a ftruncate operation from sqe input
 */
 int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

 /**
  * perform the ftruncate operation on a file descriptor
  */
 int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags);
 
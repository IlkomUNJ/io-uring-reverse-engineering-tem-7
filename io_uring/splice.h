// SPDX-License-Identifier: GPL-2.0

/**
 * prepare a tee operation using the provided io_uring_sqe
 */
 int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

 /**
  * perform a tee operation, duplicating data from one pipe to another
  */
 int io_tee(struct io_kiocb *req, unsigned int issue_flags);
 
 /**
  * clean up resources used by splice or tee operations
  */
 void io_splice_cleanup(struct io_kiocb *req);
 
 /**
  * prepare a splice operation using the provided io_uring_sqe
  */
 int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * perform a splice operation, moving data between file descriptors
  */
 int io_splice(struct io_kiocb *req, unsigned int issue_flags);
 
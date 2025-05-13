// SPDX-License-Identifier: GPL-2.0

/**
 * perform a synchronous message ring operation directly from the SQE
 */
int io_uring_sync_msg_ring(struct io_uring_sqe *sqe);
/**
 * prepare a message ring operation from an io_uring submission queue entry
 */
int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * execute the message ring operation using the provided request
 */
int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags);
/**
 * clean up resources used by the message ring operation
 */
void io_msg_ring_cleanup(struct io_kiocb *req);

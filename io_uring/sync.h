// SPDX-License-Identifier: GPL-2.0

/**
* prepare sync_file_range request using parameters from the SQE
*/
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
* execute a non-blocking sync_file_range operation
*/
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags);

/**
* prepare fsync request using parameters from the SQE
*/
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
* execute a non-blocking fsync operation
*/
int io_fsync(struct io_kiocb *req, unsigned int issue_flags);

/**
* execute a non-blocking fallocate operation
*/
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags);

/**
* prepare fallocate request using parameters from the SQE
*/
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

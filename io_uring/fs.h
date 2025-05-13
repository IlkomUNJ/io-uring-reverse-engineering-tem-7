// SPDX-License-Identifier: GPL-2.0

int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * perform a rename operation using renameat syscall via io_uring
 */
int io_renameat(struct io_kiocb *req, unsigned int issue_flags);
/**
 * release resources allocated during renameat preparation
 */
void io_renameat_cleanup(struct io_kiocb *req);

/**
 * prepare unlinkat operation from submission queue entry
 */
int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * perform file or directory unlink using unlinkat syscall via io_uring
 */
int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags);
/**
 * release resources allocated during unlinkat preparation
 */
void io_unlinkat_cleanup(struct io_kiocb *req);

/**
 * prepare mkdirat operation from submission queue entry
 */
int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * perform directory creation using mkdirat syscall via io_uring
 */
int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags);
/**
 * release resources allocated during mkdirat preparation
 */
void io_mkdirat_cleanup(struct io_kiocb *req);

/**
 * prepare symlinkat operation from submission queue entry
 */
int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * perform symbolic link creation using symlinkat syscall via io_uring
 */
int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare linkat operation from submission queue entry
 */
int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * perform hard link creation using linkat syscall via io_uring
 */
int io_linkat(struct io_kiocb *req, unsigned int issue_flags);
/**
 * release resources allocated during linkat preparation
 */
void io_link_cleanup(struct io_kiocb *req);

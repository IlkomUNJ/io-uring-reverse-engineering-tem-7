// SPDX-License-Identifier: GPL-2.0

#if defined(CONFIG_EPOLL)
int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * prepare parameters for epoll control operation via io_uring
 */
int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags);
/**
 * prepare epoll wait operation from submission queue entry
 */
int io_epoll_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * execute epoll wait to monitor events via io_uring
 */
int io_epoll_wait(struct io_kiocb *req, unsigned int issue_flags);
#endif

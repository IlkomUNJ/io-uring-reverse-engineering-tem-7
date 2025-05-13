// SPDX-License-Identifier: GPL-2.0

/**
 * clean up any resources used by xattr operations
 */
 void io_xattr_cleanup(struct io_kiocb *req);

 /**
  * prepare a fsetxattr request from sqe input
  */
 int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * set extended attribute on an open file descriptor
  */
 int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags);
 
 /**
  * prepare a setxattr request from sqe input
  */
 int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * set extended attribute on a named file
  */
 int io_setxattr(struct io_kiocb *req, unsigned int issue_flags);
 
 /**
  * prepare a fgetxattr request from sqe input
  */
 int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * get extended attribute from an open file descriptor
  */
 int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags);
 
 /**
  * prepare a getxattr request from sqe input
  */
 int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * get extended attribute from a named file
  */
 int io_getxattr(struct io_kiocb *req, unsigned int issue_flags);
 
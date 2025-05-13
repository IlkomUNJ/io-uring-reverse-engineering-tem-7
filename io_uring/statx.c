// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "statx.h"

struct io_statx {
	struct file			*file;
	int				dfd;
	unsigned int			mask;
	unsigned int			flags;
	struct filename			*filename;
	struct statx __user		*buffer;
};


/*
 * Function: int io_statx_prep
 * Description: This function prepares the io_statx command by populating the necessary fields in the io_statx structure. It extracts the file descriptor, mask, buffer, flags, and filename from the submission queue entry (sqe). It checks for invalid input, handles errors, and sets the appropriate flags for cleanup and async execution.
 * Parameters:
 *   - req: A pointer to the io_kiocb structure that contains the I/O request context.
 *   - sqe: A pointer to the io_uring_sqe structure that contains the submission queue entry details.
 * Returns:
 *   - 0: If preparation is successful.
 *   - -EINVAL: If the input is invalid (e.g., unsupported parameters).
 *   - -EBADF: If the request contains a fixed file descriptor but is invalid.
 * Example usage:
 *   - int ret = io_statx_prep(req, sqe);
 */
 int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
	 const char __user *path;
 
	 if (sqe->buf_index || sqe->splice_fd_in)
		 return -EINVAL;
	 if (req->flags & REQ_F_FIXED_FILE)
		 return -EBADF;
 
	 sx->dfd = READ_ONCE(sqe->fd);
	 sx->mask = READ_ONCE(sqe->len);
	 path = u64_to_user_ptr(READ_ONCE(sqe->addr));
	 sx->buffer = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	 sx->flags = READ_ONCE(sqe->statx_flags);
 
	 sx->filename = getname_uflags(path, sx->flags);
 
	 if (IS_ERR(sx->filename)) {
		 int ret = PTR_ERR(sx->filename);
 
		 sx->filename = NULL;
		 return ret;
	 }
 
	 req->flags |= REQ_F_NEED_CLEANUP;
	 req->flags |= REQ_F_FORCE_ASYNC;
	 return 0;
 }
 
 /*
  * Function: int io_statx
  * Description: This function performs the actual statx system call, querying the status of the file or directory specified by the filename. It uses the parameters set in io_statx_prep and calls do_statx to fetch the requested file attributes.
  * Parameters:
  *   - req: A pointer to the io_kiocb structure that contains the I/O request context.
  *   - issue_flags: Flags used to control the behavior of the I/O request.
  * Returns:
  *   - IOU_OK: Indicates the operation was successful.
  *   - Negative value: Indicates an error code returned by do_statx (e.g., -EBADF for invalid file).
  * Example usage:
  *   - int ret = io_statx(req, issue_flags);
  */
 int io_statx(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
	 int ret;
 
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 ret = do_statx(sx->dfd, sx->filename, sx->flags, sx->mask, sx->buffer);
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 
 /*
  * Function: void io_statx_cleanup
  * Description: This function cleans up resources used by the io_statx request. It releases the memory allocated for the filename if it was successfully retrieved.
  * Parameters:
  *   - req: A pointer to the io_kiocb structure that contains the I/O request context.
  * Returns:
  *   - void: No return value as it is a cleanup function.
  * Example usage:
  *   - io_statx_cleanup(req);  // Cleans up the resources allocated by io_statx.
  */
 void io_statx_cleanup(struct io_kiocb *req)
 {
	 struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
 
	 if (sx->filename)
		 putname(sx->filename);
 }
 


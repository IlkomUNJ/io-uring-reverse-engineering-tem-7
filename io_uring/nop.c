// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "nop.h"

struct io_nop {
	/* NOTE: kiocb has the file as the first member, so don't do it here */
	struct file     *file;
	int             result;
	int		fd;
	unsigned int	flags;
};

#define NOP_FLAGS	(IORING_NOP_INJECT_RESULT | IORING_NOP_FIXED_FILE | \
			 IORING_NOP_FIXED_BUFFER | IORING_NOP_FILE)


/*
 * Function: int io_nop_prep
 * Description: This function prepares the "no operation" (NOP) command in the I/O request.
 * It validates the flags and sets the appropriate values for the result and file descriptor 
 * based on the flags in the submission queue entry (sqe).
 * Parameters:
 *   - req: A pointer to the `io_kiocb` structure, which contains the I/O control block.
 *   - sqe: A pointer to the `io_uring_sqe` structure, which contains the submission queue entry.
 * Returns:
 *   - 0 if the preparation is successful.
 *   - -EINVAL if an invalid flag is passed.
 * Example usage:
 *   - ret = io_nop_prep(req, sqe);
 */
 int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_nop *nop = io_kiocb_to_cmd(req, struct io_nop);
 
	 nop->flags = READ_ONCE(sqe->nop_flags);
	 if (nop->flags & ~NOP_FLAGS)
		 return -EINVAL;
 
	 if (nop->flags & IORING_NOP_INJECT_RESULT)
		 nop->result = READ_ONCE(sqe->len);
	 else
		 nop->result = 0;
	 if (nop->flags & IORING_NOP_FILE)
		 nop->fd = READ_ONCE(sqe->fd);
	 else
		 nop->fd = -1;
	 if (nop->flags & IORING_NOP_FIXED_BUFFER)
		 req->buf_index = READ_ONCE(sqe->buf_index);
	 return 0;
 }
 
 
 /*
  * Function: int io_nop
  * Description: This function handles the execution of the "no operation" (NOP) command. 
  * It processes the result, handles the file descriptor if necessary, and checks the buffer 
  * based on the flags provided in the `nop` structure.
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure, which contains the I/O control block.
  *   - issue_flags: Flags that control how the operation is issued.
  * Returns:
  *   - IOU_OK if the operation is successfully executed.
  *   - -EBADF if the file descriptor is invalid.
  *   - -EFAULT if a fixed buffer cannot be found.
  * Example usage:
  *   - ret = io_nop(req, issue_flags);
  */
 int io_nop(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_nop *nop = io_kiocb_to_cmd(req, struct io_nop);
	 int ret = nop->result;
 
	 if (nop->flags & IORING_NOP_FILE) {
		 if (nop->flags & IORING_NOP_FIXED_FILE) {
			 req->file = io_file_get_fixed(req, nop->fd, issue_flags);
			 req->flags |= REQ_F_FIXED_FILE;
		 } else {
			 req->file = io_file_get_normal(req, nop->fd);
		 }
		 if (!req->file) {
			 ret = -EBADF;
			 goto done;
		 }
	 }
	 if (nop->flags & IORING_NOP_FIXED_BUFFER) {
		 if (!io_find_buf_node(req, issue_flags))
			 ret = -EFAULT;
	 }
 done:
	 if (ret < 0)
		 req_set_fail(req);
	 io_req_set_res(req, nop->result, 0);
	 return IOU_OK;
 }
 

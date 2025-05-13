// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/splice.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "splice.h"

struct io_splice {
	struct file			*file_out;
	loff_t				off_out;
	loff_t				off_in;
	u64				len;
	int				splice_fd_in;
	unsigned int			flags;
	struct io_rsrc_node		*rsrc_node;
};

static int __io_splice_prep(struct io_kiocb *req,
			    const struct io_uring_sqe *sqe)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	unsigned int valid_flags = SPLICE_F_FD_IN_FIXED | SPLICE_F_ALL;

	sp->len = READ_ONCE(sqe->len);
	sp->flags = READ_ONCE(sqe->splice_flags);
	if (unlikely(sp->flags & ~valid_flags))
		return -EINVAL;
	sp->splice_fd_in = READ_ONCE(sqe->splice_fd_in);
	sp->rsrc_node = NULL;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * Function: int io_tee_prep
 * Description: Prepares the necessary data structures for the "tee" operation, which is used for copying data between two file descriptors. It ensures that the operation is valid by checking for invalid fields like splice offsets.
 * Parameters:
 *   - req: A pointer to the `io_kiocb` structure, representing the I/O control block for the request.
 *   - sqe: A pointer to the `io_uring_sqe` structure, containing the submission queue entry with the request details.
 * Returns:
 *   - int: Returns 0 on success, or a negative error code (-EINVAL) if invalid fields are found (like invalid splice offsets).
 * Example usage:
 *   - int ret = io_tee_prep(req, sqe);  // Prepares the "tee" operation based on the request and submission queue entry.
 *     if (ret == 0) {
 *         // "tee" operation is successfully prepared.
 *     } else {
 *         // Handle error.
 *     }
 */
 int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 if (READ_ONCE(sqe->splice_off_in) || READ_ONCE(sqe->off))
		 return -EINVAL;
	 return __io_splice_prep(req, sqe);
 }
 
 /*
  * Function: void io_splice_cleanup
  * Description: Cleans up resources associated with the splice operation after it has been completed, such as releasing any resource nodes associated with the file descriptors.
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure, representing the I/O control block for the request.
  * Returns:
  *   - void: This function does not return any value. It performs cleanup actions based on the request.
  * Example usage:
  *   - io_splice_cleanup(req);  // Cleans up resources after completing the splice operation.
  */
 void io_splice_cleanup(struct io_kiocb *req)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
 
	 if (sp->rsrc_node)
		 io_put_rsrc_node(req->ctx, sp->rsrc_node);
 }
 
 /*
  * Function: int io_tee
  * Description: Executes the "tee" operation, copying data from one file descriptor to another. It handles different conditions such as error handling, non-blocking flags, and releasing the resources properly.
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure, representing the I/O control block for the request.
  *   - issue_flags: Flags to control how the operation is executed, such as IO_URING_F_NONBLOCK for non-blocking behavior.
  * Returns:
  *   - int: Returns 0 on success, or a negative error code if something goes wrong during the operation (e.g., -EBADF for invalid file descriptors).
  * Example usage:
  *   - int ret = io_tee(req, issue_flags);  // Executes the "tee" operation based on the request and flags.
  *     if (ret == 0) {
  *         // "tee" operation completed successfully.
  *     } else {
  *         // Handle error.
  *     }
  */
 int io_tee(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	 struct file *out = sp->file_out;
	 unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	 struct file *in;
	 ssize_t ret = 0;
 
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 in = io_splice_get_file(req, issue_flags);
	 if (!in) {
		 ret = -EBADF;
		 goto done;
	 }
 
	 if (sp->len)
		 ret = do_tee(in, out, sp->len, flags);
 
	 if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		 fput(in);
 done:
	 if (ret != sp->len)
		 req_set_fail(req);
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 
 /*
  * Function: int io_splice_prep
  * Description: Prepares the necessary data structures for the "splice" operation, which involves moving data from one file descriptor to another, checking that the offsets and buffer are valid.
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure, representing the I/O control block for the request.
  *   - sqe: A pointer to the `io_uring_sqe` structure, containing the submission queue entry with the request details.
  * Returns:
  *   - int: Returns 0 on success, or a negative error code (-EINVAL) if there are invalid fields like offset values.
  * Example usage:
  *   - int ret = io_splice_prep(req, sqe);  // Prepares the "splice" operation based on the request and submission queue entry.
  *     if (ret == 0) {
  *         // "splice" operation is successfully prepared.
  *     } else {
  *         // Handle error.
  *     }
  */
 int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
 
	 sp->off_in = READ_ONCE(sqe->splice_off_in);
	 sp->off_out = READ_ONCE(sqe->off);
	 return __io_splice_prep(req, sqe);
 }
 
 /*
  * Function: int io_splice
  * Description: Executes the "splice" operation, moving data between file descriptors. It handles different conditions, such as whether the operation should be performed inline or asynchronously.
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure, representing the I/O control block for the request.
  * Returns:
  *   - int: Returns 0 on success, or a negative error code if the operation fails (e.g., invalid file descriptor or other issues).
  * Example usage:
  *   - int ret = io_splice(req);  // Executes the "splice" operation based on the request.
  *     if (ret == 0) {
  *         // "splice" operation completed successfully.
  *     } else {
  *         // Handle error.
  *     }
  */
 int io_splice(struct io_kiocb *req, unsigned int issue_flags)
 {
	 // Implementation for the splice operation.
 }
 
int io_splice(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	loff_t *poff_in, *poff_out;
	struct file *in;
	ssize_t ret = 0;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	in = io_splice_get_file(req, issue_flags);
	if (!in) {
		ret = -EBADF;
		goto done;
	}

	poff_in = (sp->off_in == -1) ? NULL : &sp->off_in;
	poff_out = (sp->off_out == -1) ? NULL : &sp->off_out;

	if (sp->len)
		ret = do_splice(in, poff_in, out, poff_out, sp->len, flags);

	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		fput(in);
done:
	if (ret != sp->len)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}


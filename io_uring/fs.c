// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "fs.h"

struct io_rename {
	struct file			*file;
	int				old_dfd;
	int				new_dfd;
	struct filename			*oldpath;
	struct filename			*newpath;
	int				flags;
};

struct io_unlink {
	struct file			*file;
	int				dfd;
	int				flags;
	struct filename			*filename;
};

struct io_mkdir {
	struct file			*file;
	int				dfd;
	umode_t				mode;
	struct filename			*filename;
};

struct io_link {
	struct file			*file;
	int				old_dfd;
	int				new_dfd;
	struct filename			*oldpath;
	struct filename			*newpath;
	int				flags;
}

/*
 * Function: int io_renameat_prep
 * Description: Prepares the io_kiocb structure for the rename operation by reading and validating the provided inputs.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 *   - sqe: Pointer to the io_uring_sqe structure that contains the submission queue entry data.
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function is used when preparing for the file rename operation by validating paths and flags.
 */

int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_rename *ren = io_kiocb_to_cmd(req, struct io_rename);
	const char __user *oldf, *newf;

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	ren->old_dfd = READ_ONCE(sqe->fd);
	oldf = u64_to_user_ptr(READ_ONCE(sqe->addr));
	newf = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	ren->new_dfd = READ_ONCE(sqe->len);
	ren->flags = READ_ONCE(sqe->rename_flags);

	ren->oldpath = getname(oldf);
	if (IS_ERR(ren->oldpath))
		return PTR_ERR(ren->oldpath);

	ren->newpath = getname(newf);
	if (IS_ERR(ren->newpath)) {
		putname(ren->oldpath);
		return PTR_ERR(ren->newpath);
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * Function: int io_renameat
 * Description: Executes the rename operation by calling the system-level renameat2 function.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function performs the actual file renaming operation using the system call.
 */

int io_renameat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_rename *ren = io_kiocb_to_cmd(req, struct io_rename);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_renameat2(ren->old_dfd, ren->oldpath, ren->new_dfd,
				ren->newpath, ren->flags);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * Function: void io_renameat_cleanup
 * Description: Cleans up the resources allocated during the rename operation, such as freeing memory for file paths.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 * Returns:
 *   - void: This function does not return any value.
 * Example usage:
 *   - This function is used to free the allocated memory for the old and new file paths after the rename operation.
 */

void io_renameat_cleanup(struct io_kiocb *req)
{
	struct io_rename *ren = io_kiocb_to_cmd(req, struct io_rename);

	putname(ren->oldpath);
	putname(ren->newpath);
}

/*
 * Function: int io_unlinkat_prep
 * Description: Prepares the io_kiocb structure for the unlink operation by reading and validating the provided inputs.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 *   - sqe: Pointer to the io_uring_sqe structure that contains the submission queue entry data.
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function prepares for the unlink operation by validating the file path and flags.
 */

int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_unlink *un = io_kiocb_to_cmd(req, struct io_unlink);
	const char __user *fname;

	if (sqe->off || sqe->len || sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	un->dfd = READ_ONCE(sqe->fd);

	un->flags = READ_ONCE(sqe->unlink_flags);
	if (un->flags & ~AT_REMOVEDIR)
		return -EINVAL;

	fname = u64_to_user_ptr(READ_ONCE(sqe->addr));
	un->filename = getname(fname);
	if (IS_ERR(un->filename))
		return PTR_ERR(un->filename);

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * Function: int io_unlinkat
 * Description: Executes the unlink operation by calling the system-level unlinkat function.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function performs the unlink operation using the system call to remove the file.
 */

int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_unlink *un = io_kiocb_to_cmd(req, struct io_unlink);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	if (un->flags & AT_REMOVEDIR)
		ret = do_rmdir(un->dfd, un->filename);
	else
		ret = do_unlinkat(un->dfd, un->filename);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * Function: void io_unlinkat_cleanup
 * Description: Cleans up the resources allocated during the unlink operation, such as freeing memory for the file path.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 * Returns:
 *   - void: This function does not return any value.
 * Example usage:
 *   - This function is used to free the allocated memory for the file path after the unlink operation.
 */

void io_unlinkat_cleanup(struct io_kiocb *req)
{
	struct io_unlink *ul = io_kiocb_to_cmd(req, struct io_unlink);

	putname(ul->filename);
}

/*
 * Function: int io_mkdirat_prep
 * Description: Prepares the io_kiocb structure for the mkdir operation by reading and validating the provided inputs.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 *   - sqe: Pointer to the io_uring_sqe structure that contains the submission queue entry data.
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function prepares for the mkdir operation by validating the file path and flags.
 */

int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_mkdir *mkd = io_kiocb_to_cmd(req, struct io_mkdir);
	const char __user *fname;

	if (sqe->off || sqe->rw_flags || sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	mkd->dfd = READ_ONCE(sqe->fd);
	mkd->mode = READ_ONCE(sqe->len);

	fname = u64_to_user_ptr(READ_ONCE(sqe->addr));
	mkd->filename = getname(fname);
	if (IS_ERR(mkd->filename))
		return PTR_ERR(mkd->filename);

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * Function: int io_mkdirat
 * Description: Executes the mkdir operation by calling the system-level mkdirat function.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function performs the mkdir operation using the system call to create the directory.
 */

int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_mkdir *mkd = io_kiocb_to_cmd(req, struct io_mkdir);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_mkdirat(mkd->dfd, mkd->filename, mkd->mode);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * Function: void io_mkdirat_cleanup
 * Description: Cleans up the resources allocated during the mkdir operation.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure that holds the request data.
 * Returns:
 *   - void: This function does not return any value.
 * Example usage:
 *   - This function is used to release the memory allocated for the directory path after a mkdir operation.
 */

 void io_mkdirat_cleanup(struct io_kiocb *req)
 {
	 struct io_mkdir *md = io_kiocb_to_cmd(req, struct io_mkdir);
 
	 putname(md->filename);
 }
 
 /*
  * Function: int io_symlinkat_prep
  * Description: Prepares the io_kiocb structure for the symlink operation by reading and validating the provided inputs.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  *   - sqe: Pointer to the io_uring_sqe structure that contains the submission queue entry data.
  * Returns:
  *   - 0 if successful, negative error code on failure.
  * Example usage:
  *   - This function validates the input paths for creating a symlink and prepares the structure for further execution.
  */
 
 int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_link *sl = io_kiocb_to_cmd(req, struct io_link);
	 const char __user *oldpath, *newpath;
 
	 if (sqe->len || sqe->rw_flags || sqe->buf_index || sqe->splice_fd_in)
		 return -EINVAL;
	 if (unlikely(req->flags & REQ_F_FIXED_FILE))
		 return -EBADF;
 
	 sl->new_dfd = READ_ONCE(sqe->fd);
	 oldpath = u64_to_user_ptr(READ_ONCE(sqe->addr));
	 newpath = u64_to_user_ptr(READ_ONCE(sqe->addr2));
 
	 sl->oldpath = getname(oldpath);
	 if (IS_ERR(sl->oldpath))
		 return PTR_ERR(sl->oldpath);
 
	 sl->newpath = getname(newpath);
	 if (IS_ERR(sl->newpath)) {
		 putname(sl->oldpath);
		 return PTR_ERR(sl->newpath);
	 }
 
	 req->flags |= REQ_F_NEED_CLEANUP;
	 req->flags |= REQ_F_FORCE_ASYNC;
	 return 0;
 }
 
 /*
  * Function: int io_symlinkat
  * Description: Executes the symlink operation by calling the system-level symlinkat function.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
  * Returns:
  *   - 0 if successful, negative error code on failure.
  * Example usage:
  *   - This function performs the symlink creation using the system call.
  */
 
 int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_link *sl = io_kiocb_to_cmd(req, struct io_link);
	 int ret;
 
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 ret = do_symlinkat(sl->oldpath, sl->new_dfd, sl->newpath);
 
	 req->flags &= ~REQ_F_NEED_CLEANUP;
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 
 /*
  * Function: int io_linkat_prep
  * Description: Prepares the io_kiocb structure for the link operation by reading and validating the provided inputs.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  *   - sqe: Pointer to the io_uring_sqe structure that contains the submission queue entry data.
  * Returns:
  *   - 0 if successful, negative error code on failure.
  * Example usage:
  *   - This function prepares for the link operation by validating the old and new paths.
  */
 
 int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_link *lnk = io_kiocb_to_cmd(req, struct io_link);
	 const char __user *oldf, *newf;
 
	 if (sqe->buf_index || sqe->splice_fd_in)
		 return -EINVAL;
	 if (unlikely(req->flags & REQ_F_FIXED_FILE))
		 return -EBADF;
 
	 lnk->old_dfd = READ_ONCE(sqe->fd);
	 lnk->new_dfd = READ_ONCE(sqe->len);
	 oldf = u64_to_user_ptr(READ_ONCE(sqe->addr));
	 newf = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	 lnk->flags = READ_ONCE(sqe->hardlink_flags);
 
	 lnk->oldpath = getname_uflags(oldf, lnk->flags);
	 if (IS_ERR(lnk->oldpath))
		 return PTR_ERR(lnk->oldpath);
 
	 lnk->newpath = getname(newf);
	 if (IS_ERR(lnk->newpath)) {
		 putname(lnk->oldpath);
		 return PTR_ERR(lnk->newpath);
	 }
 
	 req->flags |= REQ_F_NEED_CLEANUP;
	 req->flags |= REQ_F_FORCE_ASYNC;
	 return 0;
 }
 
 /*
  * Function: int io_linkat
  * Description: Executes the link operation by calling the system-level linkat function.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
  * Returns:
  *   - 0 if successful, negative error code on failure.
  * Example usage:
  *   - This function performs the link creation using the system call.
  */
 
 int io_linkat(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_link *lnk = io_kiocb_to_cmd(req, struct io_link);
	 int ret;
 
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 ret = do_linkat(lnk->old_dfd, lnk->oldpath, lnk->new_dfd,
				 lnk->newpath, lnk->flags);
 
	 req->flags &= ~REQ_F_NEED_CLEANUP;
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 
 /*
  * Function: void io_link_cleanup
  * Description: Cleans up the resources allocated during the link operation, such as freeing memory for file paths.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  * Returns:
  *   - void: This function does not return any value.
  * Example usage:
  *   - This function is used to free the allocated memory for the old and new file paths after the link operation.
  */
 
 void io_link_cleanup(struct io_kiocb *req)
 {
	 struct io_link *sl = io_kiocb_to_cmd(req, struct io_link);
 
	 putname(sl->oldpath);
	 putname(sl->newpath);
 }
 

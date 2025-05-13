// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/fsnotify.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "sync.h"

struct io_sync {
	struct file			*file;
	loff_t				len;
	loff_t				off;
	int				flags;
	int				mode;
};

/*
 * Function: int io_sfr_prep
 * Description: This function prepares the `io_sfr` command by extracting the necessary parameters from the submission queue entry (`sqe`). It checks for invalid fields and assigns values for the sync operation's offset, length, and flags, while marking the request for asynchronous execution.
 * Parameters:
 *   - req: A pointer to the `io_kiocb` structure that contains the I/O request context.
 *   - sqe: A pointer to the `io_uring_sqe` structure that contains the submission queue entry details.
 * Returns:
 *   - 0: If preparation is successful.
 *   - -EINVAL: If invalid fields are found in the `sqe` (e.g., unsupported parameters).
 * Example usage:
 *   - int ret = io_sfr_prep(req, sqe);
 */
 int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
 
	 if (unlikely(sqe->addr || sqe->buf_index || sqe->splice_fd_in))
		 return -EINVAL;
 
	 sync->off = READ_ONCE(sqe->off);
	 sync->len = READ_ONCE(sqe->len);
	 sync->flags = READ_ONCE(sqe->sync_range_flags);
	 req->flags |= REQ_F_FORCE_ASYNC;
 
	 return 0;
 }
 
 /*
  * Function: int io_sync_file_range
  * Description: This function performs the `sync_file_range` system call. It synchronizes the specified range of a file by flushing its dirty pages. The file's sync operation is determined based on the parameters set during the preparation step (`io_sfr_prep`).
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure that contains the I/O request context.
  *   - issue_flags: Flags used to control the behavior of the I/O request (e.g., non-blocking behavior).
  * Returns:
  *   - 0: If the synchronization was successful.
  *   - Negative value: If an error occurred (e.g., file sync failure).
  * Example usage:
  *   - int ret = io_sync_file_range(req, issue_flags);
  */
 int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	 int ret;
 
	 /* sync_file_range always requires a blocking context */
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 ret = sync_file_range(req->file, sync->off, sync->len, sync->flags);
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 
 /*
  * Function: int io_fsync_prep
  * Description: This function prepares the `fsync` command by extracting the necessary parameters from the submission queue entry (`sqe`). It checks for unsupported fields and sets the file sync flags, offset, and length for the request.
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure that contains the I/O request context.
  *   - sqe: A pointer to the `io_uring_sqe` structure that contains the submission queue entry details.
  * Returns:
  *   - 0: If preparation is successful.
  *   - -EINVAL: If the flags are invalid.
  * Example usage:
  *   - int ret = io_fsync_prep(req, sqe);
  */
 int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
 
	 if (unlikely(sqe->addr || sqe->buf_index || sqe->splice_fd_in))
		 return -EINVAL;
 
	 sync->flags = READ_ONCE(sqe->fsync_flags);
	 if (unlikely(sync->flags & ~IORING_FSYNC_DATASYNC))
		 return -EINVAL;
 
	 sync->off = READ_ONCE(sqe->off);
	 sync->len = READ_ONCE(sqe->len);
	 req->flags |= REQ_F_FORCE_ASYNC;
	 return 0;
 }
 
 /*
  * Function: int io_fsync
  * Description: This function performs the `fsync` system call, ensuring that the changes made to a file are flushed to disk. The file's sync operation is based on the parameters prepared in `io_fsync_prep`.
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure that contains the I/O request context.
  *   - issue_flags: Flags used to control the behavior of the I/O request (e.g., non-blocking behavior).
  * Returns:
  *   - 0: If the synchronization was successful.
  *   - Negative value: If an error occurred (e.g., file sync failure).
  * Example usage:
  *   - int ret = io_fsync(req, issue_flags);
  */
 int io_fsync(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	 loff_t end = sync->off + sync->len;
	 int ret;
 
	 /* fsync always requires a blocking context */
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 ret = vfs_fsync_range(req->file, sync->off, end > 0 ? end : LLONG_MAX,
				 sync->flags & IORING_FSYNC_DATASYNC);
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 
 /*
  * Function: int io_fallocate_prep
  * Description: This function prepares the `fallocate` command by extracting the necessary parameters from the submission queue entry (`sqe`). It checks for invalid fields and sets the file allocation flags, offset, and length for the request.
  * Parameters:
  *   - req: A pointer to the `io_kiocb` structure that contains the I/O request context.
  *   - sqe: A pointer to the `io_uring_sqe` structure that contains the submission queue entry details.
  * Returns:
  *   - 0: If preparation is successful.
  *   - -EINVAL: If the input is invalid (e.g., unsupported parameters).
  * Example usage:
  *   - int ret = io_fallocate_prep(req, sqe);
  */
 int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
 
	 if (sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		 return -EINVAL;
 
	 sync->off = READ_ONCE(sqe->off);
	 sync->len = READ_ONCE(sqe->addr);
	 sync->mode = READ_ONCE(sqe->len);
	 req->flags |= REQ_F_FORCE_ASYNC;
	 return 0;
 }
 
/*
 * Function: int io_fallocate
 * Description: [Masukkan penjelasan singkat mengenai apa yang dilakukan oleh fungsi ini.]
 * Parameters:
 *   - [Masukkan nama parameter dan tipe data serta deskripsi jika ada]
 * Returns:
 *   - [Jelaskan tipe data yang dikembalikan dan kondisinya]
 * Example usage:
 *   - [Berikan contoh penggunaan fungsi jika perlu]
 */


int io_fallocate(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	int ret;

	/* fallocate always requiring blocking context */
	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = vfs_fallocate(req->file, sync->mode, sync->off, sync->len);
	if (ret >= 0)
		fsnotify_modify(req->file);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}


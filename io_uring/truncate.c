// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "truncate.h"

struct io_ftrunc {
	struct file			*file;
	loff_t				len;
};


/*
 * Function: int io_ftruncate_prep
 * Description: Fungsi ini mempersiapkan permintaan untuk operasi `ftruncate` pada file. 
 *              Fungsi ini memastikan bahwa parameter yang diterima sesuai dengan persyaratan
 *              dan mengatur panjang file yang akan dipangkas berdasarkan offset yang diberikan.
 * Parameters:
 *   - req (struct io_kiocb*): Pointer ke struktur kontrol I/O yang menyimpan informasi tentang permintaan.
 *   - sqe (const struct io_uring_sqe*): Pointer ke struktur permintaan antrian yang berisi parameter untuk operasi.
 * Returns:
 *   - int: Mengembalikan 0 jika persiapan berhasil, atau kode kesalahan (-EINVAL) jika terdapat parameter yang tidak valid.
 * Example usage:
 *   - int ret = io_ftruncate_prep(req, sqe);
 *     if (ret < 0) {
 *         // Tangani kesalahan
 *     }
 */
 int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_ftrunc *ft = io_kiocb_to_cmd(req, struct io_ftrunc);
 
	 if (sqe->rw_flags || sqe->addr || sqe->len || sqe->buf_index ||
		 sqe->splice_fd_in || sqe->addr3)
		 return -EINVAL;
 
	 ft->len = READ_ONCE(sqe->off);
 
	 req->flags |= REQ_F_FORCE_ASYNC;
	 return 0;
 }
 
 /*
  * Function: int io_ftruncate
  * Description: Fungsi ini melakukan operasi `ftruncate` untuk memotong atau mengubah panjang 
  *              sebuah file sesuai dengan panjang yang ditentukan pada permintaan I/O.
  *              Fungsi ini memastikan bahwa operasi dilakukan secara sinkron, dan hanya 
  *              dijalankan jika operasi non-blocking tidak diaktifkan.
  * Parameters:
  *   - req (struct io_kiocb*): Pointer ke struktur kontrol I/O yang menyimpan informasi tentang permintaan.
  *   - issue_flags (unsigned int): Flag yang digunakan untuk menandai operasi terkait konteks.
  * Returns:
  *   - int: Mengembalikan 0 jika operasi berhasil atau kode kesalahan jika gagal.
  * Example usage:
  *   - int ret = io_ftruncate(req, issue_flags);
  *     if (ret < 0) {
  *         // Tangani kesalahan
  *     }
  */
 int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_ftrunc *ft = io_kiocb_to_cmd(req, struct io_ftrunc);
	 int ret;
 
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 ret = do_ftruncate(req->file, ft->len, 1);
 
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 

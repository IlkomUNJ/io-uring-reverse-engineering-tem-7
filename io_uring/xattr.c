// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/xattr.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "xattr.h"

struct io_xattr {
	struct file			*file;
	struct kernel_xattr_ctx		ctx;
	struct filename			*filename;
};


/*
 * Function: void io_xattr_cleanup
 * Description: Fungsi ini digunakan untuk membersihkan dan membebaskan sumber daya yang terkait 
 *              dengan perintah xattr (extended attributes). Fungsi ini membebaskan memori yang 
 *              digunakan oleh nama file dan atribut lainnya yang terkait dengan permintaan xattr.
 * Parameters:
 *   - req (struct io_kiocb*): Pointer ke struktur kontrol I/O yang mewakili permintaan I/O.
 * Returns:
 *   - void: Fungsi ini tidak mengembalikan nilai.
 * Example usage:
 *   - io_xattr_cleanup(req);
 */
 void io_xattr_cleanup(struct io_kiocb *req)
 {
	 struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
 
	 if (ix->filename)
		 putname(ix->filename);
 
	 kfree(ix->ctx.kname);
	 kvfree(ix->ctx.kvalue);
 }
 
 /*
  * Function: void io_xattr_finish
  * Description: Fungsi ini digunakan untuk menyelesaikan permintaan xattr setelah proses selesai 
  *              dengan memperbarui hasil dan membersihkan data terkait. Fungsi ini akan dipanggil 
  *              ketika operasi I/O terkait xattr selesai.
  * Parameters:
  *   - req (struct io_kiocb*): Pointer ke struktur kontrol I/O yang mewakili permintaan I/O.
  *   - ret (int): Hasil dari operasi I/O, seperti 0 untuk keberhasilan atau nilai negatif untuk kesalahan.
  * Returns:
  *   - void: Fungsi ini tidak mengembalikan nilai.
  * Example usage:
  *   - io_xattr_finish(req, ret);
  */
 void io_xattr_finish(struct io_kiocb *req, int ret)
 {
	 req->flags &= ~REQ_F_NEED_CLEANUP;
 
	 io_xattr_cleanup(req);
	 io_req_set_res(req, ret, 0);
 }
 
 /*
  * Function: int __io_getxattr_prep
  * Description: Fungsi ini menyiapkan perintah I/O untuk mengambil extended attribute (xattr) 
  *              dari file. Fungsi ini mengonversi dan memverifikasi parameter yang diterima, 
  *              serta mengalokasikan memori yang diperlukan untuk operasi tersebut.
  * Parameters:
  *   - req (struct io_kiocb*): Pointer ke struktur kontrol I/O yang mewakili permintaan I/O.
  *   - sqe (const struct io_uring_sqe*): Pointer ke struktur yang berisi data permintaan I/O yang diterima dari pengguna.
  * Returns:
  *   - int: Mengembalikan 0 jika berhasil menyiapkan perintah, atau -EINVAL jika ada parameter yang tidak valid.
  * Example usage:
  *   - int ret = __io_getxattr_prep(req, sqe);
  */
 int __io_getxattr_prep(struct io_kiocb *req,
				   const struct io_uring_sqe *sqe)
 {
	 struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	 const char __user *name;
	 int ret;
 
	 ix->filename = NULL;
	 ix->ctx.kvalue = NULL;
	 name = u64_to_user_ptr(READ_ONCE(sqe->addr));
	 ix->ctx.value = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	 ix->ctx.size = READ_ONCE(sqe->len);
	 ix->ctx.flags = READ_ONCE(sqe->xattr_flags);
 
	 if (ix->ctx.flags)
		 return -EINVAL;
 
	 ix->ctx.kname = kmalloc(sizeof(*ix->ctx.kname), GFP_KERNEL);
	 if (!ix->ctx.kname)
		 return -ENOMEM;
 
	 ret = import_xattr_name(ix->ctx.kname, name);
	 if (ret) {
		 kfree(ix->ctx.kname);
		 return ret;
	 }
 
	 req->flags |= REQ_F_NEED_CLEANUP;
	 req->flags |= REQ_F_FORCE_ASYNC;
	 return 0;
 }
 
 /*
  * Function: int io_fgetxattr_prep
  * Description: Fungsi ini mempersiapkan permintaan I/O untuk mendapatkan extended attribute 
  *              (xattr) berdasarkan file descriptor yang diberikan. 
  * Parameters:
  *   - req (struct io_kiocb*): Pointer ke struktur kontrol I/O yang mewakili permintaan I/O.
  *   - sqe (const struct io_uring_sqe*): Pointer ke struktur yang berisi data permintaan I/O yang diterima dari pengguna.
  * Returns:
  *   - int: Mengembalikan 0 jika berhasil menyiapkan perintah, atau kode kesalahan lainnya.
  * Example usage:
  *   - int ret = io_fgetxattr_prep(req, sqe);
  */
 int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 return __io_getxattr_prep(req, sqe);
 }
 
 /*
  * Function: int io_getxattr_prep
  * Description: Fungsi ini mempersiapkan permintaan I/O untuk mendapatkan extended attribute 
  *              (xattr) berdasarkan nama file yang diberikan. 
  * Parameters:
  *   - req (struct io_kiocb*): Pointer ke struktur kontrol I/O yang mewakili permintaan I/O.
  *   - sqe (const struct io_uring_sqe*): Pointer ke struktur yang berisi data permintaan I/O yang diterima dari pengguna.
  * Returns:
  *   - int: Mengembalikan 0 jika berhasil menyiapkan perintah, atau kode kesalahan lainnya.
  * Example usage:
  *   - int ret = io_getxattr_prep(req, sqe);
  */
 int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	 const char __user *path;
	 int ret;
 
	 if (unlikely(req->flags & REQ_F_FIXED_FILE))
		 return -EBADF;
 
	 ret = __io_getxattr_prep(req, sqe);
	 if (ret)
		 return ret;
 
	 path = u64_to_user_ptr(READ_ONCE(sqe->addr3));
 
	 ix->filename = getname(path);
	 if (IS_ERR(ix->filename))
		 return PTR_ERR(ix->filename);
 
	 return 0;
 }
 
/*
 * Function: int io_fgetxattr
 * Description: [Masukkan penjelasan singkat mengenai apa yang dilakukan oleh fungsi ini.]
 * Parameters:
 *   - [Masukkan nama parameter dan tipe data serta deskripsi jika ada]
 * Returns:
 *   - [Jelaskan tipe data yang dikembalikan dan kondisinya]
 * Example usage:
 *   - [Berikan contoh penggunaan fungsi jika perlu]
 */


int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = file_getxattr(req->file, &ix->ctx);
	io_xattr_finish(req, ret);
	return IOU_OK;
}


/*
 * Function: int io_getxattr
 * Description: [Masukkan penjelasan singkat mengenai apa yang dilakukan oleh fungsi ini.]
 * Parameters:
 *   - [Masukkan nama parameter dan tipe data serta deskripsi jika ada]
 * Returns:
 *   - [Jelaskan tipe data yang dikembalikan dan kondisinya]
 * Example usage:
 *   - [Berikan contoh penggunaan fungsi jika perlu]
 */


int io_getxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = filename_getxattr(AT_FDCWD, ix->filename, LOOKUP_FOLLOW, &ix->ctx);
	ix->filename = NULL;
	io_xattr_finish(req, ret);
	return IOU_OK;
}

static int __io_setxattr_prep(struct io_kiocb *req,
			const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *name;
	int ret;

	ix->filename = NULL;
	name = u64_to_user_ptr(READ_ONCE(sqe->addr));
	ix->ctx.cvalue = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	ix->ctx.kvalue = NULL;
	ix->ctx.size = READ_ONCE(sqe->len);
	ix->ctx.flags = READ_ONCE(sqe->xattr_flags);

	ix->ctx.kname = kmalloc(sizeof(*ix->ctx.kname), GFP_KERNEL);
	if (!ix->ctx.kname)
		return -ENOMEM;

	ret = setxattr_copy(name, &ix->ctx);
	if (ret) {
		kfree(ix->ctx.kname);
		return ret;
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}


/*
 * Function: int io_setxattr_prep
 * Description: [Masukkan penjelasan singkat mengenai apa yang dilakukan oleh fungsi ini.]
 * Parameters:
 *   - [Masukkan nama parameter dan tipe data serta deskripsi jika ada]
 * Returns:
 *   - [Jelaskan tipe data yang dikembalikan dan kondisinya]
 * Example usage:
 *   - [Berikan contoh penggunaan fungsi jika perlu]
 */


int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *path;
	int ret;

	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	ret = __io_setxattr_prep(req, sqe);
	if (ret)
		return ret;

	path = u64_to_user_ptr(READ_ONCE(sqe->addr3));

	ix->filename = getname(path);
	if (IS_ERR(ix->filename))
		return PTR_ERR(ix->filename);

	return 0;
}


/*
 * Function: int io_fsetxattr_prep
 * Description: [Masukkan penjelasan singkat mengenai apa yang dilakukan oleh fungsi ini.]
 * Parameters:
 *   - [Masukkan nama parameter dan tipe data serta deskripsi jika ada]
 * Returns:
 *   - [Jelaskan tipe data yang dikembalikan dan kondisinya]
 * Example usage:
 *   - [Berikan contoh penggunaan fungsi jika perlu]
 */


int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_setxattr_prep(req, sqe);
}


/*
 * Function: int io_fsetxattr
 * Description: [Masukkan penjelasan singkat mengenai apa yang dilakukan oleh fungsi ini.]
 * Parameters:
 *   - [Masukkan nama parameter dan tipe data serta deskripsi jika ada]
 * Returns:
 *   - [Jelaskan tipe data yang dikembalikan dan kondisinya]
 * Example usage:
 *   - [Berikan contoh penggunaan fungsi jika perlu]
 */


int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = file_setxattr(req->file, &ix->ctx);
	io_xattr_finish(req, ret);
	return IOU_OK;
}


/*
 * Function: int io_setxattr
 * Description: [Masukkan penjelasan singkat mengenai apa yang dilakukan oleh fungsi ini.]
 * Parameters:
 *   - [Masukkan nama parameter dan tipe data serta deskripsi jika ada]
 * Returns:
 *   - [Jelaskan tipe data yang dikembalikan dan kondisinya]
 * Example usage:
 *   - [Berikan contoh penggunaan fungsi jika perlu]
 */


int io_setxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = filename_setxattr(AT_FDCWD, ix->filename, LOOKUP_FOLLOW, &ix->ctx);
	ix->filename = NULL;
	io_xattr_finish(req, ret);
	return IOU_OK;
}


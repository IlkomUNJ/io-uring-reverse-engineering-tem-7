// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_RSRC_H
#define IOU_RSRC_H

#include <linux/io_uring_types.h>
#include <linux/lockdep.h>

#define IO_VEC_CACHE_SOFT_CAP		256

enum {
	IORING_RSRC_FILE		= 0,
	IORING_RSRC_BUFFER		= 1,
};

struct io_rsrc_node {
	unsigned char			type;
	int				refs;

	u64 tag;
	union {
		unsigned long file_ptr;
		struct io_mapped_ubuf *buf;
	};
};

enum {
	IO_IMU_DEST	= 1 << ITER_DEST,
	IO_IMU_SOURCE	= 1 << ITER_SOURCE,
};

struct io_mapped_ubuf {
	u64		ubuf;
	unsigned int	len;
	unsigned int	nr_bvecs;
	unsigned int    folio_shift;
	refcount_t	refs;
	unsigned long	acct_pages;
	void		(*release)(void *);
	void		*priv;
	bool		is_kbuf;
	u8		dir;
	struct bio_vec	bvec[] __counted_by(nr_bvecs);
};

struct io_imu_folio_data {
	/* Head folio can be partially included in the fixed buf */
	unsigned int	nr_pages_head;
	/* For non-head/tail folios, has to be fully included */
	unsigned int	nr_pages_mid;
	unsigned int	folio_shift;
	unsigned int	nr_folios;
};

/**
 * initialize resource cache for the io_uring context
 */
bool io_rsrc_cache_init(struct io_ring_ctx *ctx);

/**
 * free resource cache associated with the io_uring context
 */
void io_rsrc_cache_free(struct io_ring_ctx *ctx);

/**
 * allocate a new io_rsrc_node from the context
 */
struct io_rsrc_node *io_rsrc_node_alloc(struct io_ring_ctx *ctx, int type);

/**
 * free a resource node and return it to the cache
 */
void io_free_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node);

/**
 * free the memory used by a resource data object
 */
void io_rsrc_data_free(struct io_ring_ctx *ctx, struct io_rsrc_data *data);

/**
 * allocate memory for resource data
 */
int io_rsrc_data_alloc(struct io_rsrc_data *data, unsigned nr);

/**
 * find the buffer node associated with the given request
 */
struct io_rsrc_node *io_find_buf_node(struct io_kiocb *req,
				      unsigned issue_flags);

/**
 * import a registered buffer into an iov_iter for use
 */
int io_import_reg_buf(struct io_kiocb *req, struct iov_iter *iter,
			u64 buf_addr, size_t len, int ddir,
			unsigned issue_flags);

/**
 * import a registered vector into an iov_iter for use
 */
int io_import_reg_vec(int ddir, struct iov_iter *iter,
			struct io_kiocb *req, struct iou_vec *vec,
			unsigned nr_iovs, unsigned issue_flags);

/**
 * prepare a registered iovec from user-provided iovec
 */
int io_prep_reg_iovec(struct io_kiocb *req, struct iou_vec *iv,
			const struct iovec __user *uvec, size_t uvec_segs);

/**
 * clone registered buffers from userspace into the context
 */
int io_register_clone_buffers(struct io_ring_ctx *ctx, void __user *arg);

/**
 * unregister all previously registered buffers
 */
int io_sqe_buffers_unregister(struct io_ring_ctx *ctx);

/**
 * register user-provided buffers with optional tags
 */
int io_sqe_buffers_register(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned int nr_args, u64 __user *tags);

/**
 * unregister all previously registered files
 */
int io_sqe_files_unregister(struct io_ring_ctx *ctx);

/**
 * register user-provided file descriptors with optional tags
 */
int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
			  unsigned nr_args, u64 __user *tags);

/**
 * update a subset of registered files
 */
int io_register_files_update(struct io_ring_ctx *ctx, void __user *arg,
			     unsigned nr_args);

/**
 * update registered resources like buffers or files
 */
int io_register_rsrc_update(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned size, unsigned type);

/**
 * register new resources into the io_uring context
 */
int io_register_rsrc(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int size, unsigned int type);

/**
 * validate that a user-provided iovec is safe and correct
 */
int io_buffer_validate(struct iovec *iov);

/**
 * check if a series of pages can be coalesced into a buffer region
 */
bool io_check_coalesce_buffer(struct page **page_array, int nr_pages,
			      struct io_imu_folio_data *data);

/**
 * update files using information from a request
 */
int io_files_update(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare a request for updating registered files
 */
int io_files_update_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * account locked memory usage for a user
 */
int __io_account_mem(struct user_struct *user, unsigned long nr_pages);

/**
 * unaccount previously locked memory usage
 */
static inline void __io_unaccount_mem(struct user_struct *user,
				      unsigned long nr_pages)
{
	atomic_long_sub(nr_pages, &user->locked_vm);
}

/**
 * free internal iovec vector memory
 */
void io_vec_free(struct iou_vec *iv);

/**
 * reallocate memory for an iovec vector
 */
int io_vec_realloc(struct iou_vec *iv, unsigned nr_entries);

/**
 * reset iovec pointer and count in the internal vector
 */
static inline void io_vec_reset_iovec(struct iou_vec *iv,
				      struct iovec *iovec, unsigned nr)
{
	io_vec_free(iv);
	iv->iovec = iovec;
	iv->nr = nr;
}

/**
 * free vector memory if KASAN is enabled
 */
static inline void io_alloc_cache_vec_kasan(struct iou_vec *iv)
{
	if (IS_ENABLED(CONFIG_KASAN))
		io_vec_free(iv);
}

#endif

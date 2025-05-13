// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_KBUF_H
#define IOU_KBUF_H

#include <uapi/linux/io_uring.h>
#include <linux/io_uring_types.h>

enum {
	/* ring mapped provided buffers */
	IOBL_BUF_RING	= 1,
	/* buffers are consumed incrementally rather than always fully */
	IOBL_INC	= 2,
};

struct io_buffer_list {
	/*
	 * If ->buf_nr_pages is set, then buf_pages/buf_ring are used. If not,
	 * then these are classic provided buffers and ->buf_list is used.
	 */
	union {
		struct list_head buf_list;
		struct io_uring_buf_ring *buf_ring;
	};
	__u16 bgid;

	/* below is for ring provided buffers */
	__u16 buf_nr_pages;
	__u16 nr_entries;
	__u16 head;
	__u16 mask;

	__u16 flags;

	struct io_mapped_region region;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};

enum {
	/* can alloc a bigger vec */
	KBUF_MODE_EXPAND	= 1,
	/* if bigger vec allocated, free old one */
	KBUF_MODE_FREE		= 2,
};

struct buf_sel_arg {
	struct iovec *iovs;
	size_t out_len;
	size_t max_len;
	unsigned short nr_iovs;
	unsigned short mode;
};

void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
			      unsigned int issue_flags);
int io_buffers_select(struct io_kiocb *req, struct buf_sel_arg *arg,
		      unsigned int issue_flags);
/**
 * non-destructively check availability of buffers for a request
 */
int io_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg);
/**
 * free all provided buffers and associated memory in this context
 */
void io_destroy_buffers(struct io_ring_ctx *ctx);

/**
 * prepare to remove previously provided buffers from the ring
 */
int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * remove provided buffers associated with a request
 */
int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare to register new provided buffers with the ring
 */
int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * register user-provided buffers for future use in I/O
 */
int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags);

/**
 * register a mapped buffer ring with the given context
 */
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);
/**
 * unregister a previously registered provided buffer ring
 */
int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);
/**
 * return status information about provided buffer registration
 */
int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg);

/**
 * attempt to recycle a selected buffer from legacy buffer list
 */
bool io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags);
/**
 * drop any selected legacy buffer reference for this request
 */
void io_kbuf_drop_legacy(struct io_kiocb *req);

/**
 * release one or more selected buffers and return buffer count
 */
unsigned int __io_put_kbufs(struct io_kiocb *req, int len, int nbufs);

/**
 * commit buffer usage to the buffer list after successful I/O
 */
bool io_kbuf_commit(struct io_kiocb *req,
		    struct io_buffer_list *bl, int len, int nr);

/**
 * retrieve memory region associated with a given buffer group ID
 */
struct io_mapped_region *io_pbuf_get_region(struct io_ring_ctx *ctx,
					    unsigned int bgid);

/**
 * try to recycle a ring-mapped buffer and reset relevant flags
 */
static inline bool io_kbuf_recycle_ring(struct io_kiocb *req)
{
	/*
	 * We don't need to recycle for REQ_F_BUFFER_RING, we can just clear
	 * the flag and hence ensure that bl->head doesn't get incremented.
	 * If the tail has already been incremented, hang on to it.
	 * The exception is partial io, that case we should increment bl->head
	 * to monopolize the buffer.
	 */
	if (req->buf_list) {
		req->buf_index = req->buf_list->bgid;
		req->flags &= ~(REQ_F_BUFFER_RING|REQ_F_BUFFERS_COMMIT);
		return true;
	}
	return false;
}

static inline bool io_do_buffer_select(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_BUFFER_SELECT))
		return false;
	return !(req->flags & (REQ_F_BUFFER_SELECTED|REQ_F_BUFFER_RING));
}

static inline bool io_kbuf_recycle(struct io_kiocb *req, unsigned issue_flags)
{
	if (req->flags & REQ_F_BL_NO_RECYCLE)
		return false;
	if (req->flags & REQ_F_BUFFER_SELECTED)
		return io_kbuf_recycle_legacy(req, issue_flags);
	if (req->flags & REQ_F_BUFFER_RING)
		return io_kbuf_recycle_ring(req);
	return false;
}

static inline unsigned int io_put_kbuf(struct io_kiocb *req, int len,
				       unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, 1);
}

static inline unsigned int io_put_kbufs(struct io_kiocb *req, int len,
					int nbufs, unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, nbufs);
}
#endif

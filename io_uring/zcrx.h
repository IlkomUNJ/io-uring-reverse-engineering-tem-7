// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZC_RX_H
#define IOU_ZC_RX_H

#include <linux/io_uring_types.h>
#include <linux/socket.h>
#include <net/page_pool/types.h>
#include <net/net_trackers.h>

struct io_zcrx_area {
	struct net_iov_area	nia;
	struct io_zcrx_ifq	*ifq;
	atomic_t		*user_refs;

	bool			is_mapped;
	u16			area_id;
	struct page		**pages;

	/* freelist */
	spinlock_t		freelist_lock ____cacheline_aligned_in_smp;
	u32			free_count;
	u32			*freelist;
};

struct io_zcrx_ifq {
	struct io_ring_ctx		*ctx;
	struct io_zcrx_area		*area;

	struct io_uring			*rq_ring;
	struct io_uring_zcrx_rqe	*rqes;
	u32				rq_entries;
	u32				cached_rq_head;
	spinlock_t			rq_lock;

	u32				if_rxq;
	struct device			*dev;
	struct net_device		*netdev;
	netdevice_tracker		netdev_tracker;
	spinlock_t			lock;
};

#if defined(CONFIG_IO_URING_ZCRX)

/**
 * register a zero-copy receive interface queue to the uring context
 */
int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
			 struct io_uring_zcrx_ifq_reg __user *arg);

/**
 * unregister all registered zero-copy receive interface queues
 */
void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx);

/**
 * shut down all zero-copy receive interface queues
 */
void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx);

/**
 * perform zero-copy receive from socket into interface queue
 */
int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
		 struct socket *sock, unsigned int flags,
		 unsigned issue_flags, unsigned int *len);

#else

/**
 * return unsupported error if zero-copy receive is not enabled
 */
static inline int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
					struct io_uring_zcrx_ifq_reg __user *arg)
{
	return -EOPNOTSUPP;
}

/**
 * no-op if zero-copy receive is not enabled
 */
static inline void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}

/**
 * no-op shutdown if zero-copy receive is not enabled
 */
static inline void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}

/**
 * return unsupported error for zero-copy receive if not enabled
 */
static inline int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
			       struct socket *sock, unsigned int flags,
			       unsigned issue_flags, unsigned int *len)
{
	return -EOPNOTSUPP;
}
#endif

/**
 * execute zero-copy receive operation
 */
int io_recvzc(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare a zero-copy receive operation from sqe input
 */
int io_recvzc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

#endif

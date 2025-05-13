// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/eventfd.h>
#include <linux/eventpoll.h>
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>

#include "io-wq.h"
#include "eventfd.h"

struct io_ev_fd {
	struct eventfd_ctx	*cq_ev_fd;
	unsigned int		eventfd_async;
	/* protected by ->completion_lock */
	unsigned		last_cq_tail;
	refcount_t		refs;
	atomic_t		ops;
	struct rcu_head		rcu;
};

enum {
	IO_EVENTFD_OP_SIGNAL_BIT,
};

static void io_eventfd_free(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_ctx_put(ev_fd->cq_ev_fd);
	kfree(ev_fd);
}

static void io_eventfd_put(struct io_ev_fd *ev_fd)
{
	if (refcount_dec_and_test(&ev_fd->refs))
		call_rcu(&ev_fd->rcu, io_eventfd_free);
}

static void io_eventfd_do_signal(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_signal_mask(ev_fd->cq_ev_fd, EPOLL_URING_WAKE);
	io_eventfd_put(ev_fd);
}

static void io_eventfd_release(struct io_ev_fd *ev_fd, bool put_ref)
{
	if (put_ref)
		io_eventfd_put(ev_fd);
	rcu_read_unlock();
}

/*
 * Function: io_eventfd_signal
 * Description: Signals the eventfd associated with the IO ring context, triggering an event to notify waiting tasks.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 * Returns:
 *   - void: This function does not return any value.
 * Example usage:
 *   - This function is used to signal the eventfd in the IO ring context, notifying tasks waiting for the event.
 */
void io_eventfd_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);
	if (ev_fd)
		io_eventfd_release(ev_fd, __io_eventfd_signal(ev_fd));
}

/*
 * Function: io_eventfd_flush_signal
 * Description: Flushes the eventfd signal by checking if the event queue tail has advanced and triggering the eventfd signal if necessary.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 * Returns:
 *   - void: This function does not return any value.
 * Example usage:
 *   - This function is used to ensure that the eventfd signal is triggered when necessary, typically after a CQE is added to the completion queue.
 */
void io_eventfd_flush_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);
	if (ev_fd) {
		bool skip, put_ref = true;

		/*
		 * Eventfd should only get triggered when at least one event
		 * has been posted. Some applications rely on the eventfd
		 * notification count only changing IFF a new CQE has been
		 * added to the CQ ring. There's no dependency on 1:1
		 * relationship between how many times this function is called
		 * (and hence the eventfd count) and number of CQEs posted to
		 * the CQ ring.
		 */
		spin_lock(&ctx->completion_lock);
		skip = ctx->cached_cq_tail == ev_fd->last_cq_tail;
		ev_fd->last_cq_tail = ctx->cached_cq_tail;
		spin_unlock(&ctx->completion_lock);

		if (!skip)
			put_ref = __io_eventfd_signal(ev_fd);

		io_eventfd_release(ev_fd, put_ref);
	}
}

/*
 * Function: io_eventfd_register
 * Description: Registers an eventfd object to be used with the IO ring context for signaling.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 *   - arg: Pointer to the user-space argument containing the eventfd file descriptor.
 *   - eventfd_async: Boolean indicating whether the eventfd should be used asynchronously.
 * Returns:
 *   - 0 if successful, negative error code otherwise.
 * Example usage:
 *   - This function is used to register an eventfd for the IO ring context, enabling asynchronous signaling.
 */
int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int eventfd_async)
{
	struct io_ev_fd *ev_fd;
	__s32 __user *fds = arg;
	int fd;

	ev_fd = rcu_dereference_protected(ctx->io_ev_fd,
					lockdep_is_held(&ctx->uring_lock));
	if (ev_fd)
		return -EBUSY;

	if (copy_from_user(&fd, fds, sizeof(*fds)))
		return -EFAULT;

	ev_fd = kmalloc(sizeof(*ev_fd), GFP_KERNEL);
	if (!ev_fd)
		return -ENOMEM;

	ev_fd->cq_ev_fd = eventfd_ctx_fdget(fd);
	if (IS_ERR(ev_fd->cq_ev_fd)) {
		int ret = PTR_ERR(ev_fd->cq_ev_fd);

		kfree(ev_fd);
		return ret;
	}

	spin_lock(&ctx->completion_lock);
	ev_fd->last_cq_tail = ctx->cached_cq_tail;
	spin_unlock(&ctx->completion_lock);

	ev_fd->eventfd_async = eventfd_async;
	ctx->has_evfd = true;
	refcount_set(&ev_fd->refs, 1);
	atomic_set(&ev_fd->ops, 0);
	rcu_assign_pointer(ctx->io_ev_fd, ev_fd);
	return 0;
}

/*
 * Function: io_eventfd_unregister
 * Description: Unregisters the eventfd associated with the IO ring context.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 * Returns:
 *   - 0 if successful, -ENXIO if no eventfd was registered.
 * Example usage:
 *   - This function is used to unregister the eventfd object and release associated resources.
 */
int io_eventfd_unregister(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = rcu_dereference_protected(ctx->io_ev_fd,
					lockdep_is_held(&ctx->uring_lock));
	if (ev_fd) {
		ctx->has_evfd = false;
		rcu_assign_pointer(ctx->io_ev_fd, NULL);
		io_eventfd_put(ev_fd);
		return 0;
	}

	return -ENXIO;
}



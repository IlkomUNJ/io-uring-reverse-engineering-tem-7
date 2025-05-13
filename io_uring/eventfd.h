
struct io_ring_ctx;
int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int eventfd_async);
/**
 * unregister previously registered eventfd from the context
 */
int io_eventfd_unregister(struct io_ring_ctx *ctx);

/**
 * flush pending eventfd signals associated with the context
 */
void io_eventfd_flush_signal(struct io_ring_ctx *ctx);
/**
 * signal eventfd associated with the context
 */
void io_eventfd_signal(struct io_ring_ctx *ctx);

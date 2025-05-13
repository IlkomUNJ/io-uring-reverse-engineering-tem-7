// SPDX-License-Identifier: GPL-2.0

 struct io_sq_data {
	refcount_t		refs;
	atomic_t		park_pending;
	struct mutex		lock;

	/* ctx's that are using this sqd */
	struct list_head	ctx_list;

	struct task_struct	*thread;
	struct wait_queue_head	wait;

	unsigned		sq_thread_idle;
	int			sq_cpu;
	pid_t			task_pid;
	pid_t			task_tgid;

	u64			work_time;
	unsigned long		state;
	struct completion	exited;
};

/**
 * create a submission queue polling thread for the given context
 */
int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);

/**
 * finalize and clean up the SQ thread for a given context
 */
void io_sq_thread_finish(struct io_ring_ctx *ctx);

/**
 * stop the SQ polling thread and wait for it to exit
 */
void io_sq_thread_stop(struct io_sq_data *sqd);

/**
 * park (suspend) the SQ polling thread
 */
void io_sq_thread_park(struct io_sq_data *sqd);

/**
 * unpark (resume) the SQ polling thread
 */
void io_sq_thread_unpark(struct io_sq_data *sqd);

/**
 * decrease the reference count and free sqd if it reaches zero
 */
void io_put_sq_data(struct io_sq_data *sqd);

/**
 * wait for submission queue activity (used in SQPOLL mode)
 */
void io_sqpoll_wait_sq(struct io_ring_ctx *ctx);

/**
 * get the CPU affinity mask for the SQPOLL worker thread
 */
int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask);

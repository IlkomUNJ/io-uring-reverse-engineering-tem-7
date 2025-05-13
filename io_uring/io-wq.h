#ifndef INTERNAL_IO_WQ_H
#define INTERNAL_IO_WQ_H

#include <linux/refcount.h>
#include <linux/io_uring_types.h>

struct io_wq;

enum {
	IO_WQ_WORK_CANCEL	= 1,
	IO_WQ_WORK_HASHED	= 2,
	IO_WQ_WORK_UNBOUND	= 4,
	IO_WQ_WORK_CONCURRENT	= 16,

	IO_WQ_HASH_SHIFT	= 24,	/* upper 8 bits are used for hash key */
};

enum io_wq_cancel {
	IO_WQ_CANCEL_OK,	/* cancelled before started */
	IO_WQ_CANCEL_RUNNING,	/* found, running, and attempted cancelled */
	IO_WQ_CANCEL_NOTFOUND,	/* work not found */
};

typedef struct io_wq_work *(free_work_fn)(struct io_wq_work *);
/**
 * asynchronous work function executed by an io-wq worker
 */
typedef void (io_wq_work_fn)(struct io_wq_work *);

struct io_wq_hash {
	refcount_t refs;
	unsigned long map;
	struct wait_queue_head wait;
};

/**
 * free memory associated with the given hash if refcount reaches zero
 */
static inline void io_wq_put_hash(struct io_wq_hash *hash)
{
	if (refcount_dec_and_test(&hash->refs))
/**
 * free dynamically allocated memory
 */
		kfree(hash);
}

struct io_wq_data {
	struct io_wq_hash *hash;
	struct task_struct *task;
	io_wq_work_fn *do_work;
	free_work_fn *free_work;
};

/**
 * create a new io-wq instance with given worker configuration
 */
struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data);
/**
 * begin shutdown sequence for the given io-wq instance
 */
void io_wq_exit_start(struct io_wq *wq);
/**
 * drop reference and release all resources of io-wq before task exit
 */
void io_wq_put_and_exit(struct io_wq *wq);

/**
 * submit a new work item to the io-wq workqueue
 */
void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work);
/**
 * associate a work item with a specific hash key for serialized execution
 */
void io_wq_hash_work(struct io_wq_work *work, void *val);

/**
 * retrieve or assign CPU affinity mask for io-wq workers
 */
int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask);
/**
 * query or update the maximum number of io-wq workers
 */
int io_wq_max_workers(struct io_wq *wq, int *new_count);
/**
 * check if current process is marked as stopped io-wq worker
 */
bool io_wq_worker_stopped(void);

/**
 * check if work item uses hashed (serialized) execution model
 */
static inline bool __io_wq_is_hashed(unsigned int work_flags)
{
	return work_flags & IO_WQ_WORK_HASHED;
}
/**
 * check if the given work is flagged as hashed work
 */

static inline bool io_wq_is_hashed(struct io_wq_work *work)
{
	return __io_wq_is_hashed(atomic_read(&work->flags));
}

typedef bool (work_cancel_fn)(struct io_wq_work *, void *);

enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel,
					void *data, bool cancel_all);

#if defined(CONFIG_IO_WQ)
/**
 * notify that an io-wq worker is entering sleep state
 */
extern void io_wq_worker_sleeping(struct task_struct *);
/**
 * notify that an io-wq worker is active or has resumed execution
 */
extern void io_wq_worker_running(struct task_struct *);
#else
static inline void io_wq_worker_sleeping(struct task_struct *tsk)
{
}
static inline void io_wq_worker_running(struct task_struct *tsk)
{
}
#endif

static inline bool io_wq_current_is_worker(void)
{
	return in_task() && (current->flags & PF_IO_WORKER) &&
		current->worker_private;
}
#endif

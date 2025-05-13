// SPDX-License-Identifier: GPL-2.0
/*
 * Basic worker thread pool for io_uring
 *
 * Copyright (C) 2019 Jens Axboe
 *
 */
 #include <linux/kernel.h>
 #include <linux/init.h>
 #include <linux/errno.h>
 #include <linux/sched/signal.h>
 #include <linux/percpu.h>
 #include <linux/slab.h>
 #include <linux/rculist_nulls.h>
 #include <linux/cpu.h>
 #include <linux/cpuset.h>
 #include <linux/task_work.h>
 #include <linux/audit.h>
 #include <linux/mmu_context.h>
 #include <uapi/linux/io_uring.h>
 
 #include "io-wq.h"
 #include "slist.h"
 #include "io_uring.h"
 
 #define WORKER_IDLE_TIMEOUT	(5 * HZ)
 #define WORKER_INIT_LIMIT	3
 
 enum {
	 IO_WORKER_F_UP		= 0,	/* up and active */
	 IO_WORKER_F_RUNNING	= 1,	/* account as running */
	 IO_WORKER_F_FREE	= 2,	/* worker on free list */
 };
 
 enum {
	 IO_WQ_BIT_EXIT		= 0,	/* wq exiting */
 };
 
 enum {
	 IO_ACCT_STALLED_BIT	= 0,	/* stalled on hash */
 };
 
 /*
  * One for each thread in a wq pool
  */
 struct io_worker {
	 refcount_t ref;
	 unsigned long flags;
	 struct hlist_nulls_node nulls_node;
	 struct list_head all_list;
	 struct task_struct *task;
	 struct io_wq *wq;
	 struct io_wq_acct *acct;
 
	 struct io_wq_work *cur_work;
	 raw_spinlock_t lock;
 
	 struct completion ref_done;
 
	 unsigned long create_state;
	 struct callback_head create_work;
	 int init_retries;
 
	 union {
		 struct rcu_head rcu;
		 struct delayed_work work;
	 };
 };
 
 #if BITS_PER_LONG == 64
 #define IO_WQ_HASH_ORDER	6
 #else
 #define IO_WQ_HASH_ORDER	5
 #endif
 
 #define IO_WQ_NR_HASH_BUCKETS	(1u << IO_WQ_HASH_ORDER)
 
 struct io_wq_acct {
	 /**
	  * Protects access to the worker lists.
	  */
	 raw_spinlock_t workers_lock;
 
	 unsigned nr_workers;
	 unsigned max_workers;
	 atomic_t nr_running;
 
	 /**
	  * The list of free workers.  Protected by #workers_lock
	  * (write) and RCPU (read).
	  */
	 struct hlist_nulls_head free_list;
 
	 /**
	  * The list of all workers.  Protected by #workers_lock
	  * (write) and RCPU (read).
	  */
	 struct list_head all_list;
 
	 raw_spinlock_t lock;
	 struct io_wq_work_list work_list;
	 unsigned long flags;
 };
 
 enum {
	 IO_WQ_ACCT_BOUND,
	 IO_WQ_ACCT_UNBOUND,
	 IO_WQ_ACCT_NR,
 };
 
 /*
  * Per io_wq state
  */
 struct io_wq {
	 unsigned long state;
 
	 free_work_fn *free_work;
	 io_wq_work_fn *do_work;
 
	 struct io_wq_hash *hash;
 
	 atomic_t worker_refs;
	 struct completion worker_done;
 
	 struct hlist_node cpuhp_node;
 
	 struct task_struct *task;
 
	 struct io_wq_acct acct[IO_WQ_ACCT_NR];
 
	 struct wait_queue_entry wait;
 
	 struct io_wq_work *hash_tail[IO_WQ_NR_HASH_BUCKETS];
 
	 cpumask_var_t cpu_mask;
 };
 
 static enum cpuhp_state io_wq_online;
 
 struct io_cb_cancel_data {
	 work_cancel_fn *fn;
	 void *data;
	 int nr_running;
	 int nr_pending;
	 bool cancel_all;
 };
 
 static bool create_io_worker(struct io_wq *wq, struct io_wq_acct *acct);
 static void io_wq_dec_running(struct io_worker *worker);
 static bool io_acct_cancel_pending_work(struct io_wq *wq,
					 struct io_wq_acct *acct,
					 struct io_cb_cancel_data *match);
 static void create_worker_cb(struct callback_head *cb);
 static void io_wq_cancel_tw_create(struct io_wq *wq);
 
 static bool io_worker_get(struct io_worker *worker)
 {
	 return refcount_inc_not_zero(&worker->ref);
 }
 
 static void io_worker_release(struct io_worker *worker)
 {
	 if (refcount_dec_and_test(&worker->ref))
		 complete(&worker->ref_done);
 }
 
 static inline struct io_wq_acct *io_get_acct(struct io_wq *wq, bool bound)
 {
	 return &wq->acct[bound ? IO_WQ_ACCT_BOUND : IO_WQ_ACCT_UNBOUND];
 }
 
 static inline struct io_wq_acct *io_work_get_acct(struct io_wq *wq,
						   unsigned int work_flags)
 {
	 return io_get_acct(wq, !(work_flags & IO_WQ_WORK_UNBOUND));
 }
 
 static inline struct io_wq_acct *io_wq_get_acct(struct io_worker *worker)
 {
	 return worker->acct;
 }
 
 static void io_worker_ref_put(struct io_wq *wq)
 {
	 if (atomic_dec_and_test(&wq->worker_refs))
		 complete(&wq->worker_done);
 }
 
 
 /*
  * Function: bool io_wq_worker_stopped
  * Description: Checks if the current worker has been stopped by examining the worker state.
  * Parameters:
  *   - None
  * Returns:
  *   - true if the worker has been stopped, otherwise false.
  * Example usage:
  *   - This function is used to check if the current worker thread has been marked as stopped, 
  *     typically called when performing clean-up or checking worker thread status.
  */
 
 bool io_wq_worker_stopped(void)
 {
	 struct io_worker *worker = current->worker_private;
 
	 if (WARN_ON_ONCE(!io_wq_current_is_worker()))
		 return true;
 
	 return test_bit(IO_WQ_BIT_EXIT, &worker->wq->state);
 }
 
 /*
  * Function: io_worker_cancel_cb
  * Description: Callback function that cancels a worker, updates its associated accounting and references, 
  *              and marks it as released.
  * Parameters:
  *   - worker: Pointer to the io_worker structure to be cancelled.
  * Returns:
  *   - None.
  * Example usage:
  *   - This function is invoked as part of the process to cancel a worker, typically during shutdown 
  *     or when a worker task is no longer needed.
  */
 
 static void io_worker_cancel_cb(struct io_worker *worker)
 {
	 struct io_wq_acct *acct = io_wq_get_acct(worker);
	 struct io_wq *wq = worker->wq;
 
	 atomic_dec(&acct->nr_running);
	 raw_spin_lock(&acct->workers_lock);
	 acct->nr_workers--;
	 raw_spin_unlock(&acct->workers_lock);
	 io_worker_ref_put(wq);
	 clear_bit_unlock(0, &worker->create_state);
	 io_worker_release(worker);
 }
 
 /*
  * Function: bool io_task_worker_match
  * Description: Checks if the given callback head matches the task worker that is being looked for.
  * Parameters:
  *   - cb: Pointer to the callback_head structure.
  *   - data: Pointer to the worker data being searched for.
  * Returns:
  *   - true if the callback matches the task worker, otherwise false.
  * Example usage:
  *   - This function is used when trying to find a specific worker based on a callback to 
  *     ensure that the worker is correctly matched for task handling.
  */
 
 static bool io_task_worker_match(struct callback_head *cb, void *data)
 {
	 struct io_worker *worker;
 
	 if (cb->func != create_worker_cb)
		 return false;
	 worker = container_of(cb, struct io_worker, create_work);
	 return worker == data;
 }
 
 /*
  * Function: io_worker_exit
  * Description: Cleans up a worker when it's exiting, releasing any resources, and completing 
  *              pending tasks. This function ensures that the worker is properly removed from 
  *              the worker list and that the worker's resources are freed.
  * Parameters:
  *   - worker: Pointer to the io_worker structure representing the worker exiting.
  * Returns:
  *   - None.
  * Example usage:
  *   - This function is typically called when a worker thread is terminated, ensuring all 
  *     associated tasks and resources are cleaned up before the thread exits.
  */
 
 static void io_worker_exit(struct io_worker *worker)
 {
	 struct io_wq *wq = worker->wq;
	 struct io_wq_acct *acct = io_wq_get_acct(worker);
 
	 while (1) {
		 struct callback_head *cb = task_work_cancel_match(wq->task,
						 io_task_worker_match, worker);
 
		 if (!cb)
			 break;
		 io_worker_cancel_cb(worker);
	 }
 
	 io_worker_release(worker);
	 wait_for_completion(&worker->ref_done);
 
	 raw_spin_lock(&acct->workers_lock);
	 if (test_bit(IO_WORKER_F_FREE, &worker->flags))
		 hlist_nulls_del_rcu(&worker->nulls_node);
	 list_del_rcu(&worker->all_list);
	 raw_spin_unlock(&acct->workers_lock);
	 io_wq_dec_running(worker);
	 /*
	  * this worker is a goner, clear ->worker_private to avoid any
	  * inc/dec running calls that could happen as part of exit from
	  * touching 'worker'.
	  */
	 current->worker_private = NULL;
 
	 kfree_rcu(worker, rcu);
	 io_worker_ref_put(wq);
	 do_exit(0);
 }
 
 /*
  * Function: __acquires
  * Description: Acquires a lock on the worker's accounting data and checks if the work queue has tasks ready to run.
  * Parameters:
  *   - acct: Pointer to the io_wq_acct structure representing the work queue accounting.
  * Returns:
  *   - true if there is work to do, otherwise false.
  * Example usage:
  *   - This function is used to check if there are tasks to process and ensures that the lock on the worker 
  *     is acquired before proceeding with the task execution.
  */
 
 __acquires(&acct->lock)
 {
	 raw_spin_lock(&acct->lock);
	 if (__io_acct_run_queue(acct))
		 return true;
 
	 raw_spin_unlock(&acct->lock);
	 return false;
 }
 

/*
 * Check head of free list for an available worker. If one isn't available,
 * caller must create one.
 */
 static bool io_acct_activate_free_worker(struct io_wq_acct *acct)
 {
	 // Check if there's an idle worker available in the free list
	 struct hlist_nulls_node *n;
	 struct io_worker *worker;
 
	 /*
	  * Iterate free_list and see if we can find an idle worker to
	  * activate. If a given worker is on the free_list but in the process
	  * of exiting, keep trying.
	  */
	 hlist_nulls_for_each_entry_rcu(worker, n, &acct->free_list, nulls_node) {
		 if (!io_worker_get(worker))
			 continue;
		 /*
		  * If the worker is already running, it's either already
		  * starting work or finishing work. In either case, if it does
		  * to go sleep, we'll kick off a new task for this work anyway.
		  */
		 wake_up_process(worker->task);
		 io_worker_release(worker);
		 return true;
	 }
 
	 return false;
 }
 
 /*
  * Function: io_wq_create_worker
  * Description: Creates a worker thread if necessary. 
  * Parameters:
  *   - wq: A pointer to the io_wq structure representing the work queue.
  *   - acct: A pointer to the io_wq_acct structure representing the work queue's account.
  * Returns:
  *   - true if a worker is successfully created or the max number of workers is reached.
  *   - false if a new worker could not be created.
  * Example usage:
  *   - This function is used to ensure there are enough workers in the work queue to handle incoming tasks.
  */
 static bool io_wq_create_worker(struct io_wq *wq, struct io_wq_acct *acct)
 {
	 // Check if unbounded work is being queued on an io_wq that wasn't configured for unbounded workers
	 if (unlikely(!acct->max_workers))
		 pr_warn_once("io-wq is not configured for unbound workers");
 
	 raw_spin_lock(&acct->workers_lock);
	 if (acct->nr_workers >= acct->max_workers) {
		 raw_spin_unlock(&acct->workers_lock);
		 return true;
	 }
	 acct->nr_workers++;
	 raw_spin_unlock(&acct->workers_lock);
	 atomic_inc(&acct->nr_running);
	 atomic_inc(&wq->worker_refs);
	 return create_io_worker(wq, acct);
 }
 
 /*
  * Function: io_wq_inc_running
  * Description: Increments the number of running workers in the accounting structure.
  * Parameters:
  *   - worker: A pointer to the io_worker that is starting to run.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is called when a worker starts processing tasks, incrementing the running count.
  */
 static void io_wq_inc_running(struct io_worker *worker)
 {
	 struct io_wq_acct *acct = io_wq_get_acct(worker);
 
	 atomic_inc(&acct->nr_running);
 }
 
 /*
  * Function: create_worker_cb
  * Description: Callback function that creates a new worker if needed or releases the current worker.
  * Parameters:
  *   - cb: A pointer to the callback_head structure.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is triggered after a worker finishes its task and checks if another worker needs to be created.
  */
 static void create_worker_cb(struct callback_head *cb)
 {
	 struct io_worker *worker;
	 struct io_wq *wq;
	 struct io_wq_acct *acct;
	 bool do_create = false;
 
	 worker = container_of(cb, struct io_worker, create_work);
	 wq = worker->wq;
	 acct = worker->acct;
	 raw_spin_lock(&acct->workers_lock);
 
	 if (acct->nr_workers < acct->max_workers) {
		 acct->nr_workers++;
		 do_create = true;
	 }
	 raw_spin_unlock(&acct->workers_lock);
	 if (do_create) {
		 create_io_worker(wq, acct);
	 } else {
		 atomic_dec(&acct->nr_running);
		 io_worker_ref_put(wq);
	 }
	 clear_bit_unlock(0, &worker->create_state);
	 io_worker_release(worker);
 }
 
 /*
  * Function: io_queue_worker_create
  * Description: Attempts to create a new worker and adds it to the task work queue.
  * Parameters:
  *   - worker: A pointer to the io_worker structure to be created.
  *   - acct: A pointer to the io_wq_acct structure for worker accounting.
  *   - func: The task work function to be executed for the worker.
  * Returns:
  *   - true if the worker is successfully queued for creation.
  *   - false if the worker could not be created.
  * Example usage:
  *   - This function is used to initiate the creation of a worker task, which will then be queued for execution.
  */
 static bool io_queue_worker_create(struct io_worker *worker,
									struct io_wq_acct *acct,
									task_work_func_t func)
 {
	 struct io_wq *wq = worker->wq;
 
	 /* raced with exit, just ignore create call */
	 if (test_bit(IO_WQ_BIT_EXIT, &wq->state))
		 goto fail;
	 if (!io_worker_get(worker))
		 goto fail;
 
	 /*
	  * create_state manages ownership of create_work/index. We should
	  * only need one entry per worker, as the worker going to sleep
	  * will trigger the condition, and waking will clear it once it
	  * runs the task_work.
	  */
	 if (test_bit(0, &worker->create_state) ||
		 test_and_set_bit_lock(0, &worker->create_state))
		 goto fail_release;
 
	 atomic_inc(&wq->worker_refs);
	 init_task_work(&worker->create_work, func);
	 if (!task_work_add(wq->task, &worker->create_work, TWA_SIGNAL)) {
		 /*
		  * EXIT may have been set after checking it above, check after
		  * adding the task_work and remove any creation item if it is
		  * now set. wq exit does that too, but we can have added this
		  * work item after we canceled in io_wq_exit_workers().
		  */
		 if (test_bit(IO_WQ_BIT_EXIT, &wq->state))
			 io_wq_cancel_tw_create(wq);
		 io_worker_ref_put(wq);
		 return true;
	 }
	 io_worker_ref_put(wq);
	 clear_bit_unlock(0, &worker->create_state);
 fail_release:
	 io_worker_release(worker);
 fail:
	 atomic_dec(&acct->nr_running);
	 io_worker_ref_put(wq);
	 return false;
 }
 
 /*
  * Function: io_wq_dec_running
  * Description: Decrements the running worker count and schedules a new worker if needed.
  * Parameters:
  *   - worker: A pointer to the io_worker whose running state is being decremented.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is used when a worker finishes its task and signals that it's no longer running.
  */
 static void io_wq_dec_running(struct io_worker *worker)
 {
	 struct io_wq_acct *acct = io_wq_get_acct(worker);
	 struct io_wq *wq = worker->wq;
 
	 if (!test_bit(IO_WORKER_F_UP, &worker->flags))
		 return;
 
	 if (!atomic_dec_and_test(&acct->nr_running))
		 return;
	 if (!io_acct_run_queue(acct))
		 return;
 
	 raw_spin_unlock(&acct->lock);
	 atomic_inc(&acct->nr_running);
	 atomic_inc(&wq->worker_refs);
	 io_queue_worker_create(worker, acct, create_worker_cb);
 }
 
 /*
  * Function: __io_worker_busy
  * Description: Marks the worker as busy if it is currently idle in the free list.
  * Parameters:
  *   - acct: A pointer to the io_wq_acct structure for worker accounting.
  *   - worker: A pointer to the io_worker to be marked as busy.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is called when a worker begins processing a task, and it removes the worker from the freelist.
  */
 static void __io_worker_busy(struct io_wq_acct *acct, struct io_worker *worker)
 {
	 if (test_bit(IO_WORKER_F_FREE, &worker->flags)) {
		 clear_bit(IO_WORKER_F_FREE, &worker->flags);
		 raw_spin_lock(&acct->workers_lock);
		 hlist_nulls_del_init_rcu(&worker->nulls_node);
		 raw_spin_unlock(&acct->workers_lock);
	 }
 }
 
 /*
  * Function: __io_worker_idle
  * Description: Marks the worker as idle and moves it back to the freelist.
  * Parameters:
  *   - acct: A pointer to the io_wq_acct structure for worker accounting.
  *   - worker: A pointer to the io_worker to be marked as idle.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is called when a worker finishes its task and is about to go idle, allowing it to be reused later.
  */
 
 __must_hold(acct->workers_lock)
 {
	 if (!test_bit(IO_WORKER_F_FREE, &worker->flags)) {
		 set_bit(IO_WORKER_F_FREE, &worker->flags);
		 hlist_nulls_add_head_rcu(&worker->nulls_node, &acct->free_list);
	 }
 }
 
 /*
  * Function: __io_get_work_hash
  * Description: Calculates the hash for the given work flags.
  * Parameters:
  *   - work_flags: The flags associated with the work item.
  * Returns:
  *   - A hash value derived from the work_flags.
  * Example usage:
  *   - This function is used to calculate the hash for the work, which is then used to determine the appropriate queue or bucket for the work.
  */
 static inline unsigned int __io_get_work_hash(unsigned int work_flags)
 {
	 return work_flags >> IO_WQ_HASH_SHIFT;
 }
 
 /*
  * Function: io_get_work_hash
  * Description: Retrieves the work hash for a specific work item.
  * Parameters:
  *   - work: A pointer to the io_wq_work structure representing the work item.
  * Returns:
  *   - The hash value for the work item.
  * Example usage:
  *   - This function is called to get the work hash for managing work items within the queue.
  */
 static inline unsigned int io_get_work_hash(struct io_wq_work *work)
 {
	 return __io_get_work_hash(atomic_read(&work->flags));
 }
 
 /*
  * Function: io_wait_on_hash
  * Description: Waits for work to be processed in the hash queue.
  * Parameters:
  *   - wq: A pointer to the io_wq structure.
  *   - hash: The hash value used to identify the work.
  * Returns:
  *   - true if the work is ready to be processed, otherwise false.
  * Example usage:
  *   - This function is used to wait until work corresponding to a particular hash is available for processing.
  */
 static bool io_wait_on_hash(struct io_wq *wq, unsigned int hash)
 {
	 bool ret = false;
 
	 spin_lock_irq(&wq->hash->wait.lock);
	 if (list_empty(&wq->wait.entry)) {
		 __add_wait_queue(&wq->hash->wait, &wq->wait);
		 if (!test_bit(hash, &wq->hash->map)) {
			 __set_current_state(TASK_RUNNING);
			 list_del_init(&wq->wait.entry);
			 ret = true;
		 }
	 }
	 spin_unlock_irq(&wq->hash->wait.lock);
	 return ret;
 }
 
 /*
  * Function: io_get_next_work
  * Description: Retrieves the next work item from the accounting structure.
  * Parameters:
  *   - acct: A pointer to the io_wq_acct structure representing the work queue's account.
  *   - wq: A pointer to the io_wq structure representing the work queue.
  * Returns:
  *   - A pointer to the next io_wq_work structure to be processed.
  * Example usage:
  *   - This function is used to fetch the next available work item from the queue for processing.
  */
 static struct io_wq_work *io_get_next_work(struct io_wq_acct *acct,
											struct io_wq *wq)
 {
	 // Iterate through the work list in the account to get the next available work item
	 wq_list_for_each(node, prev, &acct->work_list) {
		 unsigned int work_flags;
		 unsigned int hash;
 
		 work = container_of(node, struct io_wq_work, list);
 
		 /* not hashed, can run anytime */
		 work_flags = atomic_read(&work->flags);
		 if (!__io_wq_is_hashed(work_flags)) {
			 wq_list_del(&acct->work_list, node, prev);
			 return work;
		 }
 
		hash = __io_get_work_hash(work_flags);
		/* all items with this hash lie in [work, tail] */
		tail = wq->hash_tail[hash];

		/* hashed, can run if not already running */
		if (!test_and_set_bit(hash, &wq->hash->map)) {
			wq->hash_tail[hash] = NULL;
			wq_list_cut(&acct->work_list, &tail->list, prev);
			return work;
		}
		if (stall_hash == -1U)
			stall_hash = hash;
		/* fast forward to a next hash, for-each will fix up @prev */
		node = &tail->list;
	}

	if (stall_hash != -1U) {
		bool unstalled;

		/*
		 * Set this before dropping the lock to avoid racing with new
		 * work being added and clearing the stalled bit.
		 */
		set_bit(IO_ACCT_STALLED_BIT, &acct->flags);
		raw_spin_unlock(&acct->lock);
		unstalled = io_wait_on_hash(wq, stall_hash);
		raw_spin_lock(&acct->lock);
		if (unstalled) {
			clear_bit(IO_ACCT_STALLED_BIT, &acct->flags);
			if (wq_has_sleeper(&wq->hash->wait))
				wake_up(&wq->hash->wait);
		}
	}

	return NULL;
}

static void io_assign_current_work(struct io_worker *worker,
				   struct io_wq_work *work)
{
	if (work) {
		io_run_task_work();
		cond_resched();
	}

	raw_spin_lock(&worker->lock);
	worker->cur_work = work;
	raw_spin_unlock(&worker->lock);
}

/*
 * Called with acct->lock held, drops it before returning
 */
/*
 * Function: io_worker_handle_work
 * Description: Handles the work assigned to an I/O worker. It processes work 
 * until the account's work queue is empty or the worker is stopped.
 * Parameters:
 *   - acct: A pointer to the io_wq_acct structure representing the account 
 *     associated with the worker.
 *   - worker: A pointer to the io_worker structure representing the worker.
 * Returns:
 *   - None
 * Example usage:
 *   - This function is invoked by the worker thread to process the work assigned 
 *     to it until all tasks are completed or the worker is stopped.
 */
 static void io_worker_handle_work(struct io_wq_acct *acct, struct io_worker *worker)
 {
	 struct io_wq *wq = worker->wq;
	 bool do_kill = test_bit(IO_WQ_BIT_EXIT, &wq->state);
	 struct io_wq_work *work;
 
	 do {
		 /*
		  * If we got some work, mark us as busy. If we didn't, but
		  * the list isn't empty, it means we stalled on hashed work.
		  * Mark us stalled so we don't keep looking for work when we
		  * can't make progress, any work completion or insertion will
		  * clear the stalled flag.
		  */
		 work = io_get_next_work(acct, wq);
		 if (work) {
			 raw_spin_lock(&worker->lock);
			 worker->cur_work = work;  // Mark the current work item.
			 raw_spin_unlock(&worker->lock);
		 }
 
		 raw_spin_unlock(&acct->lock);
 
		 if (!work)
			 break;
 
		 __io_worker_busy(acct, worker);  // Mark the worker as busy.
 
		 io_assign_current_work(worker, work);
		 __set_current_state(TASK_RUNNING);  // Set the worker's state to running.
 
		 // Process all dependent work items
		 do {
			 struct io_wq_work *next_hashed, *linked;
			 unsigned int work_flags = atomic_read(&work->flags);
			 unsigned int hash = __io_wq_is_hashed(work_flags)
				 ? __io_get_work_hash(work_flags)
				 : -1U;
 
			 next_hashed = wq_next_work(work);
 
			 if (do_kill && (work_flags & IO_WQ_WORK_UNBOUND))
				 atomic_or(IO_WQ_WORK_CANCEL, &work->flags);
			 wq->do_work(work);  // Process the current work item.
			 io_assign_current_work(worker, NULL);  // Remove current work from worker.
 
			 linked = wq->free_work(work);
			 work = next_hashed;
			 if (!work && linked && !io_wq_is_hashed(linked)) {
				 work = linked;
				 linked = NULL;
			 }
			 io_assign_current_work(worker, work);
			 if (linked)
				 io_wq_enqueue(wq, linked);
 
			 if (hash != -1U && !next_hashed) {
				 spin_lock_irq(&wq->hash->wait.lock);
				 clear_bit(hash, &wq->hash->map);
				 clear_bit(IO_ACCT_STALLED_BIT, &acct->flags);
				 spin_unlock_irq(&wq->hash->wait.lock);
				 if (wq_has_sleeper(&wq->hash->wait))
					 wake_up(&wq->hash->wait);
			 }
		 } while (work);
 
		 if (!__io_acct_run_queue(acct))
			 break;
		 raw_spin_lock(&acct->lock);
	 } while (1);
 }
 
 /*
  * Function: io_wq_worker
  * Description: This function is executed by each worker thread. It continuously
  * processes work until the worker is told to exit or no more work is available.
  * Parameters:
  *   - data: A pointer to the io_worker structure representing the worker.
  * Returns:
  *   - 0 upon successful completion.
  * Example usage:
  *   - This function is used to create a worker thread that processes I/O work
  *     items from the work queue.
  */
 static int io_wq_worker(void *data)
 {
	 struct io_worker *worker = data;
	 struct io_wq_acct *acct = io_wq_get_acct(worker);
	 struct io_wq *wq = worker->wq;
	 bool exit_mask = false, last_timeout = false;
	 char buf[TASK_COMM_LEN] = {};
 
	 set_mask_bits(&worker->flags, 0,
				   BIT(IO_WORKER_F_UP) | BIT(IO_WORKER_F_RUNNING));
 
	 snprintf(buf, sizeof(buf), "iou-wrk-%d", wq->task->pid);
	 set_task_comm(current, buf);
 
	 while (!test_bit(IO_WQ_BIT_EXIT, &wq->state)) {
		 long ret;
 
		 set_current_state(TASK_INTERRUPTIBLE);
 
		 while (io_acct_run_queue(acct))
			 io_worker_handle_work(acct, worker);
 
		 raw_spin_lock(&acct->workers_lock);
		 if (last_timeout && (exit_mask || acct->nr_workers > 1)) {
			 acct->nr_workers--;
			 raw_spin_unlock(&acct->workers_lock);
			 __set_current_state(TASK_RUNNING);
			 break;
		 }
		 last_timeout = false;
		 __io_worker_idle(acct, worker);
		 raw_spin_unlock(&acct->workers_lock);
		 if (io_run_task_work())
			 continue;
		 ret = schedule_timeout(WORKER_IDLE_TIMEOUT);
		 if (signal_pending(current)) {
			 struct ksignal ksig;
 
			 if (!get_signal(&ksig))
				 continue;
			 break;
		 }
		 if (!ret) {
			 last_timeout = true;
			 exit_mask = !cpumask_test_cpu(raw_smp_processor_id(),
										   wq->cpu_mask);
		 }
	 }
 
	 if (test_bit(IO_WQ_BIT_EXIT, &wq->state) && io_acct_run_queue(acct))
		 io_worker_handle_work(acct, worker);
 
	 io_worker_exit(worker);
	 return 0;
 }
 
 /*
  * Function: io_wq_worker_running
  * Description: Marks the worker as running, ensuring that the worker is accounted 
  * for in the work queue.
  * Parameters:
  *   - tsk: A pointer to the task_struct representing the worker's task.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is used when a worker is scheduled to run to ensure that
  *     it is properly marked as running and counted in the worker stats.
  */
 void io_wq_worker_running(struct task_struct *tsk)
 {
	 struct io_worker *worker = tsk->worker_private;
 
	 if (!worker)
		 return;
	 if (!test_bit(IO_WORKER_F_UP, &worker->flags))
		 return;
	 if (test_bit(IO_WORKER_F_RUNNING, &worker->flags))
		 return;
	 set_bit(IO_WORKER_F_RUNNING, &worker->flags);
	 io_wq_inc_running(worker);
 }
 
 /*
  * Function: io_wq_worker_sleeping
  * Description: Marks the worker as sleeping, and if there are no other running workers,
  * it will wake up a free worker or create a new one.
  * Parameters:
  *   - tsk: A pointer to the task_struct representing the worker's task.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is used when a worker is going to sleep after completing work.
  *     It may trigger the creation of new workers if necessary.
  */
 void io_wq_worker_sleeping(struct task_struct *tsk)
 {
	 struct io_worker *worker = tsk->worker_private;
 
	 if (!worker)
		 return;
	 if (!test_bit(IO_WORKER_F_UP, &worker->flags))
		 return;
	 if (!test_bit(IO_WORKER_F_RUNNING, &worker->flags))
		 return;
 
	 clear_bit(IO_WORKER_F_RUNNING, &worker->flags);
	 io_wq_dec_running(worker);
 }
 
 /*
  * Function: io_init_new_worker
  * Description: Initializes a new worker, sets its CPU affinity, and adds it to the 
  * work queue and free list.
  * Parameters:
  *   - wq: A pointer to the io_wq structure representing the work queue.
  *   - acct: A pointer to the io_wq_acct structure representing the account.
  *   - worker: A pointer to the io_worker structure to be initialized.
  *   - tsk: A pointer to the task_struct representing the new worker's task.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is used to initialize and schedule a new worker in the work queue.
  */
 static void io_init_new_worker(struct io_wq *wq, struct io_wq_acct *acct,
								struct io_worker *worker, struct task_struct *tsk)
 {
	 tsk->worker_private = worker;
	 worker->task = tsk;
	 set_cpus_allowed_ptr(tsk, wq->cpu_mask);
 
	 raw_spin_lock(&acct->workers_lock);
	 hlist_nulls_add_head_rcu(&worker->nulls_node, &acct->free_list);
	 list_add_tail_rcu(&worker->all_list, &acct->all_list);
	 set_bit(IO_WORKER_F_FREE, &worker->flags);
	 raw_spin_unlock(&acct->workers_lock);
	 wake_up_new_task(tsk);
 }
 
 /*
  * Function: io_wq_work_match_all
  * Description: A match function for checking if a work item matches a given condition.
  * Parameters:
  *   - work: A pointer to the io_wq_work structure representing the work item.
  *   - data: A pointer to any additional data used for matching (in this case, always true).
  * Returns:
  *   - true if the work item matches the condition.
  * Example usage:
  *   - This function is used when iterating over work items to find matches.
  */
 static bool io_wq_work_match_all(struct io_wq_work *work, void *data)
 {
	 return true;
 }
 
 /*
  * Function: io_wq_enqueue
  * Description: Adds a work item to the work queue for processing.
  * Parameters:
  *   - wq: A pointer to the io_wq structure representing the work queue.
  *   - work: A pointer to the io_wq_work structure representing the work item.
  * Returns:
  *   - None
  * Example usage:
  *   - This function is used to insert a new work item into the work queue for processing.
  */
 void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work)
 {
	 unsigned int work_flags = atomic_read(&work->flags);
	 struct io_wq_acct *acct = io_work_get_acct(wq, work_flags);
	 struct io_cb_cancel_data match = {
		 .fn = io_wq_work_match_item,
		 .data = work,
		 .cancel_all = false,
	 };
	 bool do_create;

	/*
	 * If io-wq is exiting for this task, or if the request has explicitly
	 * been marked as one that should not get executed, cancel it here.
	 */
	if (test_bit(IO_WQ_BIT_EXIT, &wq->state) ||
	    (work_flags & IO_WQ_WORK_CANCEL)) {
		io_run_cancel(work, wq);
		return;
	}

	raw_spin_lock(&acct->lock);
	io_wq_insert_work(wq, acct, work, work_flags);
	clear_bit(IO_ACCT_STALLED_BIT, &acct->flags);
	raw_spin_unlock(&acct->lock);

	rcu_read_lock();
	do_create = !io_acct_activate_free_worker(acct);
	rcu_read_unlock();

	if (do_create && ((work_flags & IO_WQ_WORK_CONCURRENT) ||
	    !atomic_read(&acct->nr_running))) {
		bool did_create;

		did_create = io_wq_create_worker(wq, acct);
		if (likely(did_create))
			return;

		raw_spin_lock(&acct->workers_lock);
		if (acct->nr_workers) {
			raw_spin_unlock(&acct->workers_lock);
			return;
		}
		raw_spin_unlock(&acct->workers_lock);

		/* fatal condition, failed to create the first worker */
		io_acct_cancel_pending_work(wq, acct, &match);
	}
}

/*
 * Work items that hash to the same value will not be done in parallel.
 * Used to limit concurrent writes, generally hashed by inode.
 */

/*
 * Function: void io_wq_hash_work
 * Description: This function hashes a value (typically an identifier like an inode) and marks the work item with a hashed flag. The function calculates a hash for the provided value and then sets the appropriate bits in the work item's flags to mark it as hashed. This ensures that the work is grouped and processed according to its hash value, limiting parallelism for tasks that should not be executed concurrently.
 * Parameters:
 *   - work: A pointer to the `io_wq_work` structure, which represents the work item.
 *   - val: A pointer to the value (e.g., inode) that will be hashed. This value is typically used to ensure that work items with the same value are executed sequentially rather than in parallel.
 * Returns:
 *   - This function does not return any value (`void`).
 * Example usage:
 *   - This function can be used to group work items by their associated inode (or any other identifier), limiting concurrent processing:
 *     ```
 *     io_wq_hash_work(work, inode);
 *     ```
 *     In this example, `work` is the work item being hashed, and `inode` is the value used for hashing.
 */


void io_wq_hash_work(struct io_wq_work *work, void *val)
{
	unsigned int bit;

	bit = hash_ptr(val, IO_WQ_HASH_ORDER);
	atomic_or(IO_WQ_WORK_HASHED | (bit << IO_WQ_HASH_SHIFT), &work->flags);
}

static bool __io_wq_worker_cancel(struct io_worker *worker,
				  struct io_cb_cancel_data *match,
				  struct io_wq_work *work)
{
	if (work && match->fn(work, match->data)) {
		atomic_or(IO_WQ_WORK_CANCEL, &work->flags);
		__set_notify_signal(worker->task);
		return true;
	}

	return false;
}

static bool io_wq_worker_cancel(struct io_worker *worker, void *data)
{
	struct io_cb_cancel_data *match = data;

	/*
	 * Hold the lock to avoid ->cur_work going out of scope, caller
	 * may dereference the passed in work.
	 */
	raw_spin_lock(&worker->lock);
	if (__io_wq_worker_cancel(worker, match, worker->cur_work))
		match->nr_running++;
	raw_spin_unlock(&worker->lock);

	return match->nr_running && !match->cancel_all;
}

static inline void io_wq_remove_pending(struct io_wq *wq,
					struct io_wq_acct *acct,
					 struct io_wq_work *work,
					 struct io_wq_work_node *prev)
{
	unsigned int hash = io_get_work_hash(work);
	struct io_wq_work *prev_work = NULL;

	if (io_wq_is_hashed(work) && work == wq->hash_tail[hash]) {
		if (prev)
			prev_work = container_of(prev, struct io_wq_work, list);
		if (prev_work && io_get_work_hash(prev_work) == hash)
			wq->hash_tail[hash] = prev_work;
		else
			wq->hash_tail[hash] = NULL;
	}
	wq_list_del(&acct->work_list, &work->list, prev);
}

static bool io_acct_cancel_pending_work(struct io_wq *wq,
					struct io_wq_acct *acct,
					struct io_cb_cancel_data *match)
{
	struct io_wq_work_node *node, *prev;
	struct io_wq_work *work;

	raw_spin_lock(&acct->lock);
	
/*
 * Function: wq_list_for_each
 * Description: This function is used to iterate over a list of work items in the work queue (`acct->work_list`). It performs the given operation (`match->fn`) on each work item in the list. If the operation matches, the work item is removed from the list and canceled.
 * Parameters:
 *   - node: A pointer to the current list node being iterated.
 *   - prev: A pointer to the previous node in the list.
 *   - work_list: A pointer to the list that holds all the work items (`acct->work_list`).
 * Returns:
 *   - bool: The function returns `true` if a match is found and the work item was successfully canceled. Otherwise, it returns `false`.
 * Example usage:
 *   - The function could be used in a context where you want to cancel pending work items:
 *     ```
 *     wq_list_for_each(node, prev, &acct->work_list) {
 *         work = container_of(node, struct io_wq_work, list);
 *         if (!match->fn(work, match->data))
 *             continue;
 *         io_wq_remove_pending(wq, acct, work, prev);
 *         raw_spin_unlock(&acct->lock);
 *         io_run_cancel(work, wq);
 *         match->nr_pending++;
 *         return true;
 *     }
 *     raw_spin_unlock(&acct->lock);
 *     return false;
 *     ```
 */
 wq_list_for_each(node, prev, &acct->work_list) {
    work = container_of(node, struct io_wq_work, list);
    if (!match->fn(work, match->data))
        continue;
    io_wq_remove_pending(wq, acct, work, prev);
    raw_spin_unlock(&acct->lock);
    io_run_cancel(work, wq);
    match->nr_pending++;
    /* not safe to continue after unlock */
    return true;
}
raw_spin_unlock(&acct->lock);

return false;


static void io_wq_cancel_pending_work(struct io_wq *wq,
				      struct io_cb_cancel_data *match)
{
	int i;
retry:
	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		struct io_wq_acct *acct = io_get_acct(wq, i == 0);

		if (io_acct_cancel_pending_work(wq, acct, match)) {
			if (match->cancel_all)
				goto retry;
			break;
		}
	}
}

static void io_acct_cancel_running_work(struct io_wq_acct *acct,
					struct io_cb_cancel_data *match)
{
	raw_spin_lock(&acct->workers_lock);
	io_acct_for_each_worker(acct, io_wq_worker_cancel, match);
	raw_spin_unlock(&acct->workers_lock);
}

static void io_wq_cancel_running_work(struct io_wq *wq,
				       struct io_cb_cancel_data *match)
{
	rcu_read_lock();

	for (int i = 0; i < IO_WQ_ACCT_NR; i++)
		io_acct_cancel_running_work(&wq->acct[i], match);

	rcu_read_unlock();
}

enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel,
				  void *data, bool cancel_all)
{
	struct io_cb_cancel_data match = {
		.fn		= cancel,
		.data		= data,
		.cancel_all	= cancel_all,
	};

	/*
	 * First check pending list, if we're lucky we can just remove it
	 * from there. CANCEL_OK means that the work is returned as-new,
	 * no completion will be posted for it.
	 *
	 * Then check if a free (going busy) or busy worker has the work
	 * currently running. If we find it there, we'll return CANCEL_RUNNING
	 * as an indication that we attempt to signal cancellation. The
	 * completion will run normally in this case.
	 *
	 * Do both of these while holding the acct->workers_lock, to ensure that
	 * we'll find a work item regardless of state.
	 */
	io_wq_cancel_pending_work(wq, &match);
	if (match.nr_pending && !match.cancel_all)
		return IO_WQ_CANCEL_OK;

	io_wq_cancel_running_work(wq, &match);
	if (match.nr_running && !match.cancel_all)
		return IO_WQ_CANCEL_RUNNING;

	if (match.nr_running)
		return IO_WQ_CANCEL_RUNNING;
	if (match.nr_pending)
		return IO_WQ_CANCEL_OK;
	return IO_WQ_CANCEL_NOTFOUND;
}

static int io_wq_hash_wake(struct wait_queue_entry *wait, unsigned mode,
			    int sync, void *key)
{
	struct io_wq *wq = container_of(wait, struct io_wq, wait);
	int i;

	list_del_init(&wait->entry);

	rcu_read_lock();
	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		struct io_wq_acct *acct = &wq->acct[i];

		if (test_and_clear_bit(IO_ACCT_STALLED_BIT, &acct->flags))
			io_acct_activate_free_worker(acct);
	}
	rcu_read_unlock();
	return 1;
}

struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data)
{
	int ret, i;
	struct io_wq *wq;

	if (WARN_ON_ONCE(!data->free_work || !data->do_work))
		return ERR_PTR(-EINVAL);
	if (WARN_ON_ONCE(!bounded))
		return ERR_PTR(-EINVAL);

	wq = kzalloc(sizeof(struct io_wq), GFP_KERNEL);
	if (!wq)
		return ERR_PTR(-ENOMEM);

	refcount_inc(&data->hash->refs);
	wq->hash = data->hash;
	wq->free_work = data->free_work;
	wq->do_work = data->do_work;

	ret = -ENOMEM;

	if (!alloc_cpumask_var(&wq->cpu_mask, GFP_KERNEL))
		goto err;
	cpuset_cpus_allowed(data->task, wq->cpu_mask);
	wq->acct[IO_WQ_ACCT_BOUND].max_workers = bounded;
	wq->acct[IO_WQ_ACCT_UNBOUND].max_workers =
				task_rlimit(current, RLIMIT_NPROC);
	INIT_LIST_HEAD(&wq->wait.entry);
	wq->wait.func = io_wq_hash_wake;
	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		struct io_wq_acct *acct = &wq->acct[i];

		atomic_set(&acct->nr_running, 0);

		raw_spin_lock_init(&acct->workers_lock);
		INIT_HLIST_NULLS_HEAD(&acct->free_list, 0);
		INIT_LIST_HEAD(&acct->all_list);

		INIT_WQ_LIST(&acct->work_list);
		raw_spin_lock_init(&acct->lock);
	}

	wq->task = get_task_struct(data->task);
	atomic_set(&wq->worker_refs, 1);
	init_completion(&wq->worker_done);
	ret = cpuhp_state_add_instance_nocalls(io_wq_online, &wq->cpuhp_node);
	if (ret)
		goto err;

	return wq;
err:
	io_wq_put_hash(data->hash);
	free_cpumask_var(wq->cpu_mask);
	kfree(wq);
	return ERR_PTR(ret);
}

static bool io_task_work_match(struct callback_head *cb, void *data)
{
	struct io_worker *worker;

	if (cb->func != create_worker_cb && cb->func != create_worker_cont)
		return false;
	worker = container_of(cb, struct io_worker, create_work);
	return worker->wq == data;
}


/*
 * Function: void io_wq_exit_start
 * Description: This function initiates the process of shutting down a work queue (`io_wq`). It sets the `IO_WQ_BIT_EXIT` bit in the work queue's state to signal that the work queue is in the process of exiting. This is the first step to mark the work queue for cleanup and ensures that no new work is assigned to it after this signal.
 * Parameters:
 *   - wq: A pointer to the `io_wq` structure, representing the work queue that is being marked for exit.
 * Returns:
 *   - This function does not return a value.
 * Example usage:
 *   - To mark a work queue for shutdown, call the function like this:
 *     ```
 *     io_wq_exit_start(wq);
 *     ```
 *     This will signal the work queue to begin the exit process.
 */
 void io_wq_exit_start(struct io_wq *wq)
 {
	 set_bit(IO_WQ_BIT_EXIT, &wq->state);
 }
 

static void io_wq_cancel_tw_create(struct io_wq *wq)
{
	struct callback_head *cb;

	while ((cb = task_work_cancel_match(wq->task, io_task_work_match, wq)) != NULL) {
		struct io_worker *worker;

		worker = container_of(cb, struct io_worker, create_work);
		io_worker_cancel_cb(worker);
		/*
		 * Only the worker continuation helper has worker allocated and
		 * hence needs freeing.
		 */
		if (cb->func == create_worker_cont)
			kfree(worker);
	}
}

static void io_wq_exit_workers(struct io_wq *wq)
{
	if (!wq->task)
		return;

	io_wq_cancel_tw_create(wq);

	rcu_read_lock();
	io_wq_for_each_worker(wq, io_wq_worker_wake, NULL);
	rcu_read_unlock();
	io_worker_ref_put(wq);
	wait_for_completion(&wq->worker_done);

	spin_lock_irq(&wq->hash->wait.lock);
	list_del_init(&wq->wait.entry);
	spin_unlock_irq(&wq->hash->wait.lock);

	put_task_struct(wq->task);
	wq->task = NULL;
}

static void io_wq_destroy(struct io_wq *wq)
{
	struct io_cb_cancel_data match = {
		.fn		= io_wq_work_match_all,
		.cancel_all	= true,
	};

	cpuhp_state_remove_instance_nocalls(io_wq_online, &wq->cpuhp_node);
	io_wq_cancel_pending_work(wq, &match);
	free_cpumask_var(wq->cpu_mask);
	io_wq_put_hash(wq->hash);
	kfree(wq);
}


/*
 * Function: void io_wq_put_and_exit
 * Description: This function is used to gracefully shut down and clean up the work queue (`io_wq`) and its associated resources. 
 * It ensures that the work queue is properly marked as exiting, waits for all worker threads to complete, 
 * and then releases any allocated resources associated with the work queue.
 * Parameters:
 *   - wq: A pointer to the `io_wq` structure representing the work queue to be shut down and cleaned up.
 * Returns:
 *   - This function does not return a value.
 * Example usage:
 *   - To destroy a work queue and clean up its resources, you can call the function as follows:
 *     ```
 *     io_wq_put_and_exit(wq);
 *     ```
 *     This will signal that the work queue is exiting, wait for all workers to finish, and clean up resources.
 */
 void io_wq_put_and_exit(struct io_wq *wq)
 {
	 WARN_ON_ONCE(!test_bit(IO_WQ_BIT_EXIT, &wq->state));
 
	 io_wq_exit_workers(wq);
	 io_wq_destroy(wq);
 }
 

struct online_data {
	unsigned int cpu;
	bool online;
};

static bool io_wq_worker_affinity(struct io_worker *worker, void *data)
{
	struct online_data *od = data;

	if (od->online)
		cpumask_set_cpu(od->cpu, worker->wq->cpu_mask);
	else
		cpumask_clear_cpu(od->cpu, worker->wq->cpu_mask);
	return false;
}

static int __io_wq_cpu_online(struct io_wq *wq, unsigned int cpu, bool online)
{
	struct online_data od = {
		.cpu = cpu,
		.online = online
	};

	rcu_read_lock();
	io_wq_for_each_worker(wq, io_wq_worker_affinity, &od);
	rcu_read_unlock();
	return 0;
}

static int io_wq_cpu_online(unsigned int cpu, struct hlist_node *node)
{
	struct io_wq *wq = hlist_entry_safe(node, struct io_wq, cpuhp_node);

	return __io_wq_cpu_online(wq, cpu, true);
}

static int io_wq_cpu_offline(unsigned int cpu, struct hlist_node *node)
{
	struct io_wq *wq = hlist_entry_safe(node, struct io_wq, cpuhp_node);

	return __io_wq_cpu_online(wq, cpu, false);
}


/*
 * Function: int io_wq_cpu_affinity
 * Description: This function sets or gets the CPU affinity mask for a specific io_uring task. 
 * It configures the CPUs that the task's associated work queue can execute on. If a `mask` is provided, 
 * it sets the CPU affinity for the task's work queue. If no `mask` is provided, it retrieves the current allowed CPUs.
 * The function ensures that the CPU mask is a valid subset of the allowed CPUs for the task.
 * Parameters:
 *   - tctx: A pointer to the `io_uring_task` structure that represents the task for which the CPU affinity is being set or retrieved.
 *   - mask: A pointer to the CPU mask (`cpumask_var_t`) representing the CPUs to which the task can be bound. If this is `NULL`, the function will return the current allowed CPU mask.
 * Returns:
 *   - 0 if the CPU affinity is successfully set or retrieved.
 *   - -EINVAL if the provided `mask` is not a valid subset of the allowed CPUs for the task.
 *   - -ENOMEM if memory allocation for the CPU mask fails.
 * Example usage:
 *   - To set the CPU affinity for a task to CPUs 0, 1, and 2, you can call this function as follows:
 *     ```
 *     cpumask_var_t mask;
 *     cpumask_set_cpu(0, mask);
 *     cpumask_set_cpu(1, mask);
 *     cpumask_set_cpu(2, mask);
 *     io_wq_cpu_affinity(tctx, mask);
 *     ```
 *     This would bind the work queue for the `io_uring_task` (`tctx`) to CPUs 0, 1, and 2.
 */
 int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask)
 {
	 cpumask_var_t allowed_mask;
	 int ret = 0;
 
	 if (!tctx || !tctx->io_wq)
		 return -EINVAL;
 
	 if (!alloc_cpumask_var(&allowed_mask, GFP_KERNEL))
		 return -ENOMEM;
 
	 rcu_read_lock();
	 cpuset_cpus_allowed(tctx->io_wq->task, allowed_mask);
	 if (mask) {
		 if (cpumask_subset(mask, allowed_mask))
			 cpumask_copy(tctx->io_wq->cpu_mask, mask);
		 else
			 ret = -EINVAL;
	 } else {
		 cpumask_copy(tctx->io_wq->cpu_mask, allowed_mask);
	 }
	 rcu_read_unlock();
 
	 free_cpumask_var(allowed_mask);
	 return ret;
 }
 

/*
 * Set max number of unbounded workers, returns old value. If new_count is 0,
 * then just return the old value.
 */

/*
 * Function: int io_wq_max_workers
 * Description: This function sets or retrieves the maximum number of workers 
 * for a work queue. It allows the configuration of the maximum workers for 
 * both bounded and unbounded work accounts. If the `new_count` is provided, 
 * it will update the maximum worker count; otherwise, it returns the previous value.
 * Parameters:
 *   - wq: The work queue for which the maximum number of workers is being set or retrieved.
 *   - new_count: An array containing the new maximum number of workers for each account 
 *                (bounded and unbounded). If `new_count` is zero, it will not update the 
 *                value but just return the current maximum worker count.
 * Returns:
 *   - The old value of the maximum number of workers for both bounded and unbounded accounts.
 *     The returned value is stored in the `prev` array, which is used to track the 
 *     previous values before updating them.
 * Example usage:
 *   - If you want to limit the number of unbounded workers in a work queue to a certain value, 
 *     you can use this function to update the worker limits:
 *     ```
 *     int new_worker_count[2] = {50, 100};  // 50 for bounded, 100 for unbounded
 *     int old_worker_count = io_wq_max_workers(wq, new_worker_count);
 *     ```
 *     This will set the maximum workers for bounded and unbounded accounts to 50 and 100, respectively.
 */

int io_wq_max_workers(struct io_wq *wq, int *new_count)
{
	struct io_wq_acct *acct;
	int prev[IO_WQ_ACCT_NR];
	int i;

	BUILD_BUG_ON((int) IO_WQ_ACCT_BOUND   != (int) IO_WQ_BOUND);
	BUILD_BUG_ON((int) IO_WQ_ACCT_UNBOUND != (int) IO_WQ_UNBOUND);
	BUILD_BUG_ON((int) IO_WQ_ACCT_NR      != 2);

	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		if (new_count[i] > task_rlimit(current, RLIMIT_NPROC))
			new_count[i] = task_rlimit(current, RLIMIT_NPROC);
	}

	for (i = 0; i < IO_WQ_ACCT_NR; i++)
		prev[i] = 0;

	rcu_read_lock();

	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		acct = &wq->acct[i];
		raw_spin_lock(&acct->workers_lock);
		prev[i] = max_t(int, acct->max_workers, prev[i]);
		if (new_count[i])
			acct->max_workers = new_count[i];
		raw_spin_unlock(&acct->workers_lock);
	}
	rcu_read_unlock();

	for (i = 0; i < IO_WQ_ACCT_NR; i++)
		new_count[i] = prev[i];

	return 0;
}

static __init int io_wq_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN, "io-wq/online",
					io_wq_cpu_online, io_wq_cpu_offline);
	if (ret < 0)
		return ret;
	io_wq_online = ret;
	return 0;
}
subsys_initcall(io_wq_init);


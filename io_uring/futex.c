/*
 * Function: bool io_futex_cache_init
 * Description: Initializes the futex cache used for futex operations.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure containing the context.
 * Returns:
 *   - true if the cache is successfully initialized, false otherwise.
 * Example usage:
 *   - This function is called to initialize the futex cache when setting up the io_uring context.
 */

 bool io_futex_cache_init(struct io_ring_ctx *ctx)
 {
	 return io_alloc_cache_init(&ctx->futex_cache, IO_FUTEX_ALLOC_CACHE_MAX,
				 sizeof(struct io_futex_data), 0);
 }
 
 /*
  * Function: void io_futex_cache_free
  * Description: Frees the resources allocated for the futex cache.
  * Parameters:
  *   - ctx: Pointer to the io_ring_ctx structure containing the context.
  * Returns:
  *   - void: This function does not return any value.
  * Example usage:
  *   - This function is called to free the futex cache after it is no longer needed.
  */
 
 void io_futex_cache_free(struct io_ring_ctx *ctx)
 {
	 io_alloc_cache_free(&ctx->futex_cache, kfree);
 }
 
 /*
  * Function: void __io_futex_complete
  * Description: Completes the futex request and processes the task work.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  *   - tw: The token for the task work to be processed.
  * Returns:
  *   - void: This function does not return any value.
  * Example usage:
  *   - This function is called to complete the futex request after the futex operation is finished.
  */
 
 static void __io_futex_complete(struct io_kiocb *req, io_tw_token_t tw)
 {
	 req->async_data = NULL;
	 hlist_del_init(&req->hash_node);
	 io_req_task_complete(req, tw);
 }
 
 /*
  * Function: void io_futex_complete
  * Description: Completes the futex request by releasing its resources and completing the task work.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  *   - tw: The token for the task work to be processed.
  * Returns:
  *   - void: This function does not return any value.
  * Example usage:
  *   - This function is called when the futex operation is complete to finalize the request.
  */
 
 static void io_futex_complete(struct io_kiocb *req, io_tw_token_t tw)
 {
	 struct io_ring_ctx *ctx = req->ctx;
 
	 io_tw_lock(ctx, tw);
	 io_cache_free(&ctx->futex_cache, req->async_data);
	 __io_futex_complete(req, tw);
 }
 
 /*
  * Function: void io_futexv_complete
  * Description: Completes the futex vector request by unqueuing multiple futex operations and completing the task work.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  *   - tw: The token for the task work to be processed.
  * Returns:
  *   - void: This function does not return any value.
  * Example usage:
  *   - This function is called when the futex vector operation is complete to finalize the request.
  */
 
 static void io_futexv_complete(struct io_kiocb *req, io_tw_token_t tw)
 {
	 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	 struct futex_vector *futexv = req->async_data;
 
	 io_tw_lock(req->ctx, tw);
 
	 if (!iof->futexv_unqueued) {
		 int res;
 
		 res = futex_unqueue_multiple(futexv, iof->futex_nr);
		 if (res != -1)
			 io_req_set_res(req, res, 0);
	 }
 
	 kfree(req->async_data);
	 req->flags &= ~REQ_F_ASYNC_DATA;
	 __io_futex_complete(req, tw);
 }
 
 /*
  * Function: bool io_futexv_claim
  * Description: Claims a futex vector for the current operation.
  * Parameters:
  *   - iof: Pointer to the io_futex structure containing futex operation data.
  * Returns:
  *   - true if the futex vector is successfully claimed, false otherwise.
  * Example usage:
  *   - This function is used to ensure that a futex vector is not already claimed before proceeding with the operation.
  */
 
 static bool io_futexv_claim(struct io_futex *iof)
 {
	 if (test_bit(0, &iof->futexv_owned) ||
		 test_and_set_bit_lock(0, &iof->futexv_owned))
		 return false;
	 return true;
 }
 
 /*
  * Function: bool __io_futex_cancel
  * Description: Cancels a futex operation if it is in progress.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure that holds the request data.
  * Returns:
  *   - true if the cancellation was successful, false otherwise.
  * Example usage:
  *   - This function is called to cancel an ongoing futex operation, such as a futex wait or futex vector operation.
  */
 
 static bool __io_futex_cancel(struct io_kiocb *req)
 {
	 /* futex wake already done or in progress */
	 if (req->opcode == IORING_OP_FUTEX_WAIT) {
		 struct io_futex_data *ifd = req->async_data;
 
		 if (!futex_unqueue(&ifd->q))
			 return false;
		 req->io_task_work.func = io_futex_complete;
	 } else {
		 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
 
		 if (!io_futexv_claim(iof))
			 return false;
		 req->io_task_work.func = io_futexv_complete;
	 }
 
	 hlist_del_init(&req->hash_node);
	 io_req_set_res(req, -ECANCELED, 0);
	 io_req_task_work_add(req);
	 return true;
 }
 
 /*
  * Function: int io_futex_cancel
  * Description: Cancels futex operations for a given io_uring context and cancel data.
  * Parameters:
  *   - ctx: Pointer to the io_ring_ctx structure containing the io_uring context.
  *   - cd: Pointer to the io_cancel_data structure that specifies which operations to cancel.
  *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
  * Returns:
  *   - 0 if successful, negative error code on failure.
  * Example usage:
  *   - This function is called to cancel one or more futex operations in the io_uring context.
  */
 
 int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
			 unsigned int issue_flags)
 {
	 return io_cancel_remove(ctx, cd, issue_flags, &ctx->futex_list, __io_futex_cancel);
 }
 
 /*
  * Function: bool io_futex_remove_all
  * Description: Removes all futex operations from the specified io_uring context.
  * Parameters:
  *   - ctx: Pointer to the io_ring_ctx structure containing the io_uring context.
  *   - tctx: Pointer to the io_uring task structure representing the task to remove operations for.
  *   - cancel_all: Flag indicating whether to cancel all operations.
  * Returns:
  *   - true if operations were removed, false otherwise.
  * Example usage:
  *   - This function is used to remove all futex operations related to a specific task from the io_uring context.
  */
 
 bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  bool cancel_all)
 {
	 return io_cancel_remove_all(ctx, tctx, &ctx->futex_list, cancel_all, __io_futex_cancel);
 }
 
 /*
  * Function: int io_futex_prep
  * Description: Prepares the futex operation for execution by validating the input parameters.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure containing the request data.
  *   - sqe: Pointer to the io_uring_sqe structure containing the submission queue entry data.
  * Returns:
  *   - 0 if successful, negative error code on failure.
  * Example usage:
  *   - This function validates the input parameters for a futex operation, such as the futex address and value.
  */
 
 int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	 u32 flags;
 
	 if (unlikely(sqe->len || sqe->futex_flags || sqe->buf_index ||
			  sqe->file_index))
		 return -EINVAL;
 
	 iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	 iof->futex_val = READ_ONCE(sqe->addr2);
	 iof->futex_mask = READ_ONCE(sqe->addr3);
	 flags = READ_ONCE(sqe->fd);
 
	 if (flags & ~FUTEX2_VALID_MASK)
		 return -EINVAL;
 
	 iof->futex_flags = futex2_to_flags(flags);
	 if (!futex_flags_valid(iof->futex_flags))
		 return -EINVAL;
 
	 if (!futex_validate_input(iof->futex_flags, iof->futex_val) ||
		 !futex_validate_input(iof->futex_flags, iof->futex_mask))
		 return -EINVAL;
 
	 return 0;
 }
 
 /*
  * Function: void io_futex_wakev_fn
  * Description: Wake function for the futex vector that processes futex wake operations.
  * Parameters:
  *   - wake_q: Pointer to the wake_q_head structure containing the wake queue.
  *   - q: Pointer to the futex_q structure representing the futex operation to be woken.
  * Returns:
  *   - void: This function does not return any value.
  * Example usage:
  *   - This function is used to wake a futex operation after it has been queued and ready for processing.
  */
 
 static void io_futex_wakev_fn(struct wake_q_head *wake_q, struct futex_q *q)
 {
	 struct io_kiocb *req = q->wake_data;
	 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
 
	 if (!io_futexv_claim(iof))
		 return;
	 if (unlikely(!__futex_wake_mark(q)))
		 return;
 
	 io_req_set_res(req, 0, 0);
	 req->io_task_work.func = io_futexv_complete;
	 io_req_task_work_add(req);
 }
 
 /*
  * Function: int io_futexv_prep
  * Description: Prepares the futex vector operation for execution by validating the input parameters.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure containing the request data.
  *   - sqe: Pointer to the io_uring_sqe structure containing the submission queue entry data.
  * Returns:
  *   - 0 if successful, negative error code on failure.
  * Example usage:
  *   - This function validates the input parameters for a futex vector operation, such as the futex vector address and the number of elements.
  */
 
 int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	 struct futex_vector *futexv;
	 int ret;
 
	 /* No flags or mask supported for waitv */
	 if (unlikely(sqe->fd || sqe->buf_index || sqe->file_index ||
			  sqe->addr2 || sqe->futex_flags || sqe->addr3))
		 return -EINVAL;
 
	 iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	 iof->futex_nr = READ_ONCE(sqe->len);
	 if (!iof->futex_nr || iof->futex_nr > FUTEX_WAITV_MAX)
		 return -EINVAL;
 
	 futexv = kcalloc(iof->futex_nr, sizeof(*futexv), GFP_KERNEL);
	 if (!futexv)
		 return -ENOMEM;
 
	 ret = futex_parse_waitv(futexv, iof->uwaitv, iof->futex_nr,
				 io_futex_wakev_fn, req);
	 if (ret) {
		 kfree(futexv);
		 return ret;
	 }
 
	 iof->futexv_owned = 0;
	 iof->futexv_unqueued = 0;
	 req->flags |= REQ_F_ASYNC_DATA;
	 req->async_data = futexv;
	 return 0;
 }
 
 /*
  * Function: int io_futexv_wait
  * Description: Waits for multiple futex operations to complete.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure containing the request data.
  *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
  * Returns:
  *   - 0 if successful, negative error code on failure.
  * Example usage:
  *   - This function is called to wait for multiple futex operations to complete.
  */
 
 int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	 struct futex_vector *futexv = req->async_data;
	 struct io_ring_ctx *ctx = req->ctx;
	 int ret, woken = -1;
 
	 io_ring_submit_lock(ctx, issue_flags);
 
	 ret = futex_wait_multiple_setup(futexv, iof->futex_nr, &woken);
 
	 /*
	  * Error case, ret is < 0. Mark the request as failed.
	  */
	 if (unlikely(ret < 0)) {
		 io_ring_submit_unlock(ctx, issue_flags);
		 req_set_fail(req);
		 io_req_set_res(req, ret, 0);
		 kfree(futexv);
		 req->async_data = NULL;
		 req->flags &= ~REQ_F_ASYNC_DATA;
		 return IOU_OK;
	 }
 

	/*
	 * 0 return means that we successfully setup the waiters, and that
	 * nobody triggered a wakeup while we were doing so. If the wakeup
	 * happened post setup, the task_work will be run post this issue and
	 * under the submission lock. 1 means We got woken while setting up,
	 * let that side do the completion. Note that
	 * futex_wait_multiple_setup() will have unqueued all the futexes in
	 * this case. Mark us as having done that already, since this is
	 * different from normal wakeup.
	 */
	if (!ret) {
		/*
		 * If futex_wait_multiple_setup() returns 0 for a
		 * successful setup, then the task state will not be
		 * runnable. This is fine for the sync syscall, as
		 * it'll be blocking unless we already got one of the
		 * futexes woken, but it obviously won't work for an
		 * async invocation. Mark us runnable again.
		 */
		__set_current_state(TASK_RUNNING);
		hlist_add_head(&req->hash_node, &ctx->futex_list);
	} else {
		iof->futexv_unqueued = 1;
		if (woken != -1)
			io_req_set_res(req, woken, 0);
	}

	io_ring_submit_unlock(ctx, issue_flags);
	return IOU_ISSUE_SKIP_COMPLETE;
}


/*
 * Function: int io_futex_wait
 * Description: Waits for a futex operation to complete by setting up the necessary waiters and handling possible wakeups.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure containing the request data.
 *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
 * Returns:
 *   - IOU_ISSUE_SKIP_COMPLETE if the operation was successfully set up and the task is either not yet woken or will be woken later.
 *   - IOU_OK if the operation was successfully completed.
 * Example usage:
 *   - This function is called when a futex wait operation is initiated, preparing the waiters and handling wakeups.
 */

 int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	 struct io_ring_ctx *ctx = req->ctx;
	 struct io_futex_data *ifd = NULL;
	 struct futex_hash_bucket *hb;
	 int ret;
 
	 if (!iof->futex_mask) {
		 ret = -EINVAL;
		 goto done;
	 }
 
	 io_ring_submit_lock(ctx, issue_flags);
	 ifd = io_cache_alloc(&ctx->futex_cache, GFP_NOWAIT);
	 if (!ifd) {
		 ret = -ENOMEM;
		 goto done_unlock;
	 }
 
	 req->async_data = ifd;
	 ifd->q = futex_q_init;
	 ifd->q.bitset = iof->futex_mask;
	 ifd->q.wake = io_futex_wake_fn;
	 ifd->req = req;
 
	 ret = futex_wait_setup(iof->uaddr, iof->futex_val, iof->futex_flags,
					&ifd->q, &hb);
	 if (!ret) {
		 hlist_add_head(&req->hash_node, &ctx->futex_list);
		 io_ring_submit_unlock(ctx, issue_flags);
 
		 futex_queue(&ifd->q, hb, NULL);
		 return IOU_ISSUE_SKIP_COMPLETE;
	 }
 
 done_unlock:
	 io_ring_submit_unlock(ctx, issue_flags);
 done:
	 if (ret < 0)
		 req_set_fail(req);
	 io_req_set_res(req, ret, 0);
	 kfree(ifd);
	 return IOU_OK;
 }
 
 /*
  * Function: int io_futex_wake
  * Description: Wakes up futexes that are waiting for a specific condition by sending a wake signal.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure containing the request data.
  *   - issue_flags: Flags that control the issue behavior (e.g., non-blocking).
  * Returns:
  *   - IOU_OK if the wakeup operation was successful.
  * Example usage:
  *   - This function is called to wake up one or more futexes that are waiting for a specific condition to be met.
  */
 
 int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	 int ret;
 
	 /*
	  * Strict flags - ensure that waking 0 futexes yields a 0 result.
	  * See commit 43adf8449510 ("futex: FLAGS_STRICT") for details.
	  */
	 ret = futex_wake(iof->uaddr, FLAGS_STRICT | iof->futex_flags,
			  iof->futex_val, iof->futex_mask);
	 if (ret < 0)
		 req_set_fail(req);
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 
 /*
  * Function: int io_futexv_prep
  * Description: Prepares a futex vector operation by setting up the necessary futex structures and validation.
  * Parameters:
  *   - req: Pointer to the io_kiocb structure containing the request data.
  *   - sqe: Pointer to the io_uring_sqe structure containing the submission queue entry data.
  * Returns:
  *   - 0 if the futex vector operation is successfully prepared.
  *   - Negative error code if preparation fails.
  * Example usage:
  *   - This function validates and prepares a futex vector operation to be executed asynchronously.
  */
 
 int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	 struct futex_vector *futexv;
	 int ret;
 
	 /* No flags or mask supported for waitv */
	 if (unlikely(sqe->fd || sqe->buf_index || sqe->file_index ||
			  sqe->addr2 || sqe->futex_flags || sqe->addr3))
		 return -EINVAL;
 
	 iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	 iof->futex_nr = READ_ONCE(sqe->len);
	 if (!iof->futex_nr || iof->futex_nr > FUTEX_WAITV_MAX)
		 return -EINVAL;
 
	 futexv = kcalloc(iof->futex_nr, sizeof(*futexv), GFP_KERNEL);
	 if (!futexv)
		 return -ENOMEM;
 
	 ret = futex_parse_waitv(futexv, iof->uwaitv, iof->futex_nr,
				 io_futex_wakev_fn, req);
	 if (ret) {
		 kfree(futexv);
		 return ret;
	 }
 
	 iof->futexv_owned = 0;
	 iof->futexv_unqueued = 0;
	 req->flags |= REQ_F_ASYNC_DATA;
	 req->async_data = futexv;
	 return 0;
 }
 


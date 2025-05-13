# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter
io_sync        | sync.c     | file (struct file *), len (loff_t), off (loff_t), flags (int), mode (int) | io_sfr_prep                   | sync.c          | local variable
io_sync        | sync.c     | file (struct file *), len (loff_t), off (loff_t), flags (int), mode (int) | io_sync_file_range             | sync.c          | local variable
io_sync        | sync.c     | file (struct file *), len (loff_t), off (loff_t), flags (int), mode (int) | io_kiocb_to_cmd                | sync.c          | local variable
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_sfr_prep                   | sync.c          | function parameter
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_sync_file_range             | sync.c          | function parameter
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_kiocb_to_cmd                | sync.c          | function parameter
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_sfr_prep                   | sync.h          | function parameter
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_sync_file_range             | sync.h          | function parameter
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_fsync_prep                  | sync.h          | function parameter
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_fsync                       | sync.h          | function parameter
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_fallocate                   | sync.h          | function parameter
io_kiocb       | io_uring.h   | data, flags, op, status, result, io_task | io_fallocate_prep              | sync.h          | function parameter
io_wq           | tctx.h       | hash_map (io_wq_hash *), refs (refcount_t), wait (wait_queue_head_t) | io_init_wq_offload             | tctx.c          | local variable
io_ring_ctx     | io_uring.h   | uring_lock (mutex), hash_map (io_wq_hash *), sq_entries (unsigned int) | io_init_wq_offload             | tctx.c          | function parameter
io_wq_hash      | tctx.h       | refs (refcount_t), wait (wait_queue_head_t)          | io_init_wq_offload             | tctx.c          | local variable
io_ring_ctx     | io_uring.h   | uring_lock (mutex), hash_map (io_wq_hash *), sq_entries (unsigned int) | io_uring_add_tctx_node         | tctx.h          | function parameter
io_uring_task   | tctx.h       | last (io_ring_ctx *)                               | io_uring_add_tctx_node         | tctx.h          | function parameter
io_timeout      | timeout.c    | file (struct file *), off (u32), target_seq (u32), repeats (u32), list (list_head), head (io_kiocb *), prev (io_kiocb *) | io_is_timeout_noseq            | timeout.c       | function parameter
io_timeout_rem  | timeout.c    | file (struct file *), addr (u64), ts (timespec64), flags (u32), ltimeout (bool) | io_is_timeout_noseq            | timeout.c       | function parameter
io_timeout_data   | timeout.h    | req (io_kiocb *), timer (hrtimer), ts (timespec64), mode (hrtimer_mode), flags (u32) | io_disarm_linked_timeout      | timeout.h       | function parameter
io_kiocb          | io_uring.h   | data, flags, op, status, result, io_task, and others | io_disarm_linked_timeout      | timeout.h       | function parameter
io_ftrunc       | truncate.c   | file (struct file *), len (loff_t)                 | io_ftruncate_prep              | truncate.c      | function parameter
io_ftrunc       | truncate.c   | file (struct file *), len (loff_t)                 | io_ftruncate                  | truncate.c      | function parameter
io_kiocb        | io_uring.h   | data, flags, op, status, result, io_task, and others | io_ftruncate_prep              | truncate.c      | function parameter
io_kiocb        | io_uring.h   | data, flags, op, status, result, io_task, and others | io_ftruncate_prep              | truncate.h      | function parameter
io_kiocb        | io_uring.h   | data, flags, op, status, result, io_task, and others | io_ftruncate                  | truncate.h      | function parameter


If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.

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
io_async_cmd | io_uring/uring_cmd.c | list_head, work_struct, io_uring_cmd_data, io_vec_cache, io_uring_sqe[] | io_cmd_cache_free | uring_cmd.c | Function parameter | Function parameter 
| | | | io_uring_cmd_prep_setup | uring_cmd.c | Local variable | Local variable 
| | | | io_uring_cmd_import_fixed_vec | uring_cmd.c | Local variable | Local variable 
| | | | io_req_uring_cleanup | uring_cmd.c | Local variable | Local variable 
io_waitid | io_uring/waitid.c  | file *, int which, pid_t upid, int options, atomic_t refs, wait_queue_head *, siginfo __user *, waitid_info | io_waitid_finish | io_uring/waitid.c | Menyimpan data utama untuk operasi waitid |
| | | | io_waitid_copy_si | io_uring/waitid.c   | Menyalin hasil ke user space 
| | | | io_waitid_free | io_uring/waitid.c  | Membebaskan memori async waitid 
| | | | io_waitid_cb | io_uring/waitid.c  | Digunakan dalam callback setelah child exit 
| | | | io_waitid_complete | io_uring/waitid.c | Menyelesaikan permintaan waitid 
| | | | __io_waitid_cancel | io_uring/waitid.c  | Digunakan untuk pembatalan request 
| | | | io_waitid_drop_issue_ref  | io_uring/waitid.c | Mengelola reference count waitid 
| | | | io_waitid | io_uring/waitid.c | Eksekusi utama permintaan waitid 
| | | | io_waitid_prep | io_uring/waitid.c | Mempersiapkan permintaan waitid 
| | | | io_waitid_wait | io_uring/waitid.c | Fungsi pemicu callback dari waitqueue 
io_waitid_async  | io_uring/waitid.h  | io_kiocb *, wait_opts | io_uring/waitid.c | io_waitid_cb | Menyimpan informasi async dan wait_opts untuk waitid 
| | | | io_waitid | io_uring/waitid.c | Dialokasikan untuk permintaan waitid 
| | | | io_waitid_drop_issue_ref | io_uring/waitid.c | Digunakan untuk menghapus dari waitqueue 
| | | | io_waitid_wait | io_uring/waitid.c | Setup callback saat child exit 
io_xattr | io_uring/xattr.c | struct file *, struct kernel_xattr_ctx ctx, struct filename * | io_fgetxattr_prep | io_uring/xattr.c | Menyiapkan operasi get xattr via file descriptor    
| | | | io_fgetxattr | io_uring/xattr.c | Mendapatkan xattr dari file descriptor 
| | | | io_getxattr_prep | io_uring/xattr.c | Menyiapkan getxattr dari path 
| | | | io_getxattr | io_uring/xattr.c | Mendapatkan xattr berdasarkan path 
| | | | io_setxattr_prep | io_uring/xattr.c | Menyiapkan setxattr berdasarkan path                
| | | | io_setxattr | io_uring/xattr.c | Menyimpan atribut berdasarkan path                  
| | | | io_fsetxattr_prep | io_uring/xattr.c | Menyiapkan setxattr dengan file descriptor          
| | | | io_fsetxattr | io_uring/xattr.c | Menyimpan atribut menggunakan file descriptor       
| | | | io_xattr_cleanup | io_uring/xattr.c | Membersihkan alokasi dinamis dalam struct io_xattr 
| | | | io_xattr_finish | io_uring/xattr.c | Menyelesaikan dan membersihkan permintaan xattr 
io_zcrx_area | io_uring/zcrx.h | net_iov_area, *ifq, *user_refs, is_mapped, area_id, **pages, freelist_lock, free_count, *freelist | io_zcrx_iov_to_area | io_uring/zcrx.c | return value 
| | | | io_zcrx_alloc_fallback | io_uring/zcrx.c | parameter, local variable 
| | | | io_zcrx_copy_chunk     | io_uring/zcrx.c | accessed via ifq->area  
io_zcrx_ifq  | io_uring/zcrx.h | *ctx, *area, *rq_ring, *rqes, rq_entries, cached_rq_head, rq_lock, if_rxq, *dev, *netdev, netdev_tracker, lock | io_zcrx_recv_skb      | io_uring/zcrx.c | local variable, passed to functions 
| | | | io_zcrx_copy_chunk    | io_uring/zcrx.c | parameter via req->ifq            
| | | | io_zcrx_tcp_recvmsg   | io_uring/zcrx.c | function parameter                  
| | | | io_zcrx_recv    | io_uring/zcrx.c | function parameter  

If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.

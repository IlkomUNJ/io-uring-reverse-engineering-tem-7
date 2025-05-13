# Task 2: Dependency Injection
For this assigment, we want a little clarity regarding what kind of functions being imported and used on each source. Do note, we record all function actually being used by the source including function defined by itself if actually used inside the file. For the sake of completion, it's better if you straight disregard include list on the source. Instead, trace each function being used to the declared source.

Source | Libary | Function utilized | Time Used
-------|--------|--------------| ------------------
alloc_cache.h | /include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | arch/x86/include/asm/string_64.h| memset | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | alloc_cache.h | io_cache_alloc_new | 1
| | alloc_cache.h | io_alloc_cache_put | 1
| | linux/mm/slub.c | kfree | 1
| rsrc.h | rsrc.h | io_account_mem          | 1         
| rsrc.h | rsrc.h | io_unaccount_mem        | 1         
| rsrc.h | rsrc.h | __io_account_mem        | 1         
| rsrc.h | rsrc.h | __io_unaccount_mem      | 1         
| rsrc.h | rsrc.h | io_register_rsrc        | 1         
| rsrc.h | rsrc.h | io_register_rsrc_file   | 1         
| rsrc.h | rsrc.h | io_unregister_rsrc_file | 1     
| rsrc.c | linux/compiler.h | READ_ONCE  | 1         
| rsrc.c | linux/slab.h | kfree           | 4         
| rsrc.c | linux/slab.h | kmalloc_array  | 1         
| rsrc.c | linux/mm.h   | kvfree          | 4         
| rsrc.c | linux/mm.h   | kvmalloc        | 1         
| rsrc.c | linux/mm.h   | kvmalloc_array | 2         
| rsrc.c | linux/string.h | memset           | 3         
| rsrc.c | linux/string.h | memcpy           | 1         
| rsrc.c | linux/string.h | memcmp           | 1         
| rsrc.c | asm/uaccess.h  | copy_from_user | 11        
| rsrc.c | asm/uaccess.h  | copy_to_user   | 1         
| rsrc.c | asm/barrier.h  | unlikely         | 14        
| rsrc.c | linux/kernel.h | WARN_ON_ONCE   | 3         
| rsrc.c | linux/kernel.h | IS_ERR          | 7         
| rsrc.c | linux/kernel.h | PTR_ERR         | 7         
| rsrc.c | linux/math.h   | max              | 2         
| rsrc.c | linux/math.h   | min              | 1         
| rsrc.c | linux/math.h   | min_t           | 3         
| rsrc.c | linux/overflow.h | check_add_overflow | 7         
| rsrc.c | linux/bitops.h | swap                | 1         
| rsrc.c | linux/mutex.h  | mutex_lock         | 1         
| rsrc.c  | linux/mutex.h  | mutex_lock_nested | 1         
| rsrc.c  | linux/mutex.h  | mutex_unlock       | 2         
| rsrc.c  | linux/sched.h  | fget                | 3         
| rsrc.c  | linux/sched.h  | fput                | 6         
| rsrc.c  | linux/mm_types.h | page              | 20        
| rsrc.c  | linux/mm_types.h | page_size        | 1         
| rsrc.c  | linux/mm_types.h | PageCompound      | 3         
| rsrc.c  | linux/mm_types.h | page_folio       | 3         
| rsrc.c  | linux/mm_types.h | compound_head    | 4         
| rsrc.c  | linux/mm_types.h | folio_nr_pages  | 1         
| rsrc.c  | linux/mm_types.h | folio_page_idx         | 2         
| rsrc.c  | linux/mm_types.h | folio_size              | 5         
| rsrc.c  | linux/refcount.h  | refcount_dec_and_test | 1         
| rsrc.c  | linux/refcount.h  | refcount_inc            | 1         
| rsrc.c  | linux/refcount.h  | refcount_set            | 2         
| rsrc.c  | linux/fs.h        | fput                     | 6         
| rsrc.c  | linux/uaccess.h   | u64_to_user_ptr  | 9         
| rsrc.c  | linux/types.h     | void | 19        
| rsrc.c  | linux/limits.h    | rlimit | 2         
| rsrc.c  | io_uring/alloc_cache.c | io_alloc_cache_free | 2        
| rsrc.c  | io_uring/alloc_cache.c | io_alloc_cache_init | 2        
| rsrc.c | io_uring/filetable.c | io_alloc_file_tables | 1         
| rsrc.c | io_uring/filetable.c | io_fixed_fd_install  | 1         
| rsrc.c | io_uring/filetable.c | io_free_file_tables  | 1         
| rsrc.c | io_uring/io_uring.c | io_is_uring_fops     | 2         
| rsrc.c | io_uring/io_uring.c | io_post_aux_cqe      | 1         
| rsrc.c | io_uring/memmap.c    | io_pin_pages          | 1         
| rsrc.c | io_uring/register.c  | io_uring_register_get_file | 1         
| rsrc.c | io_uring/rsrc.c  | EXPORT_SYMBOL_GPL          | 2         
| rsrc.c | io_uring/rsrc.c  | headpage_already_acct      | 2         
| rsrc.c | io_uring/rsrc.c  | __io_account_mem         | 2         
| rsrc.c | io_uring/rsrc.c  | io_account_mem             | 2         
| rsrc.c | io_uring/rsrc.c  | io_alloc_imu               | 3         
| rsrc.c | io_uring/rsrc.c  | io_buffer_account_pin     | 2         
| rsrc.c | io_uring/rsrc.c  | io_buffer_register_bvec   | 2         
| rsrc.c | io_uring/rsrc.c  | io_buffer_unmap            | 3         
| rsrc.c | io_uring/rsrc.c  | io_buffer_unregister_bvec | 2         
| rsrc.c | io_uring/rsrc.c  | io_buffer_validate         | 3         
| rsrc.c | io_uring/rsrc.c  | io_check_coalesce_buffer  | 2         
| rsrc.c | io_uring/rsrc.c  | io_clone_buffers           | 2         
| rsrc.c | io_uring/rsrc.c  | io_coalesce_buffer         | 2         
| rsrc.c | io_uring/rsrc.c  | io_estimate_bvec_size     | 2         
| rsrc.c | io_uring/rsrc.c  | io_files_update            | 1         
| rsrc.c | io_uring/rsrc.c  | io_files_update_prep      | 1         
| rsrc.c | io_uring/rsrc.c  | io_files_update_with_index_alloc | 2         
| rsrc.c | io_uring/rsrc.c  | io_find_buf_node            | 3         
| rsrc.c | io_uring/rsrc.c  | io_free_imu                  | 3         
| rsrc.c | io_uring/rsrc.c  | io_free_rsrc_node           | 1         
| rsrc.c | io_uring/rsrc.c  | io_import_fixed              | 2         
| rsrc.c | io_uring/rsrc.c  | io_import_reg_buf           | 1         
| rsrc.c | io_uring/rsrc.c  | io_import_reg_vec           | 1         
| rsrc.c | io_uring/rsrc.c  | io_kern_bvec_size           | 2         
| rsrc.c | io_uring/rsrc.c  | io_prep_reg_iovec           | 1         
| rsrc.c | io_uring/rsrc.c  | io_register_clone_buffers   | 1         
| rsrc.c | io_uring/rsrc.c  | io_register_files_update    | 1         
| rsrc.c | io_uring/rsrc.c  | io_register_rsrc             | 1         
| rsrc.c | io_uring/rsrc.c  | __io_register_rsrc_update | 4         
| rsrc.c | io_uring/rsrc.c  | io_register_rsrc_update     | 1         
| rsrc.c | io_uring/rsrc.c  | io_release_ubuf              | 2         
| rsrc.c | io_uring/rsrc.c  | io_rsrc_cache_free          | 1         
| rsrc.c | io_uring/rsrc.c  | io_rsrc_cache_init          | 1         
| rsrc.c | io_uring/rsrc.c  | io_rsrc_data_alloc          | 3         
| rsrc.c | io_uring/rsrc.c  | io_rsrc_data_free           | 4         
| rsrc.c | io_uring/rsrc.c  | io_rsrc_node_alloc          | 6         
| rsrc.c | io_uring/rsrc.c  | io_sqe_buffer_register      | 4         
| rsrc.c | io_uring/rsrc.c  | io_sqe_buffers_register   | 2         
| rsrc.c | io_uring/rsrc.c  | io_sqe_buffers_unregister | 2         
| rsrc.c | io_uring/rsrc.c  | __io_sqe_buffers_update | 2         
| rsrc.c | io_uring/rsrc.c  | io_sqe_files_register     | 2         
| rsrc.c | io_uring/rsrc.c  | io_sqe_files_unregister   | 2         
| rsrc.c | io_uring/rsrc.c  | __io_sqe_files_update   | 2         
| rsrc.c | io_uring/rsrc.c  | io_unaccount_mem           | 2         
| rsrc.c | io_uring/rsrc.c  | io_vec_fill_bvec          | 2         
| rsrc.c | io_uring/rsrc.c  | io_vec_fill_kern_bvec    | 2         
| rsrc.c | io_uring/rsrc.c  | io_vec_free                | 3         
| rsrc.c | io_uring/rsrc.c  | io_vec_realloc             | 3         
| rsrc.c | io_uring/rsrc.c  | iov_kern_bvec_size        | 2         
| rsrc.c | io_uring/rsrc.c  | validate_fixed_range       | 4  
| zcrx.h | zcrx.h | zcrx_check_enabled | 1         
| zcrx.h | zcrx.h | zcrx_test_enabled  | 1         
| zcrx.h | zcrx.h | zcrx_get_idle_buffer_hint | 1         
| zcrx.h | zcrx.h | zcrx_get_mode | 1         
| zcrx.h | zcrx.h | zcrx_set_hint | 1         
| zcrx.c | linux/dma-mapping.h | dma_map_page_attrs   | 1         
| zcrx.c | linux/dma-mapping.h | dma_unmap_page_attrs | 2         
| zcrx.c | linux/dma-mapping.h | dma_mapping_error     | 1         
| zcrx.c | linux/dma-mapping.h | dma_dev_need_sync    | 1         
| zcrx.c | linux/compiler.h    | unlikely                | 10        
| zcrx.c | linux/compiler.h    | likely                  | 1         
| zcrx.c | linux/kernel.h      | WARN_ON                | 2         
| zcrx.c | linux/kernel.h      | WARN_ON_ONCE          | 5         
| zcrx.c | linux/uaccess.h     | copy_from_user        | 3         
| zcrx.c | linux/uaccess.h     | copy_to_user          | 3         
| zcrx.c | linux/netdevice.h   | lock_sock              | 1         
| zcrx.c | linux/netdevice.h   | release_sock           | 1         
| zcrx.c | net/tcp.h           | tcp_read_sock         | 1         
| zcrx.c | net/tcp.h           | __tcp_read_sock | 2         
| zcrx.c | linux/net.h         | sock_flag          | 2         
| zcrx.c | linux/net.h         | sock_error         | 1         
| zcrx.c | linux/minmax.h      | min                 | 1         
| zcrx.c | linux/minmax.h      | min_t              | 4         
| zcrx.c | net/page_pool/helpers.h | page_pool_get_dma_addr_netmem | 2        
| zcrx.c | net/page_pool/helpers.h | netmem_to_net_iov               | 2        
| zcrx.c | net/page_pool/helpers.h | net_mp_niov_set_dma_addr      | 2        
| zcrx.c | linux/skbuff.h     | skb_shinfo               | 2         
| zcrx.c | linux/skbuff.h     | skb_headlen              | 4         
| zcrx.c | linux/skbuff.h     | skb_frag_size           | 1         
| zcrx.c | linux/skbuff.h     | skb_frag_is_net_iov   | 1         
| zcrx.c | linux/skbuff.h     | skb_walk_frags          | 1         
| zcrx.c | linux/uaccess.h    | u64_to_user_ptr        | 5         
| zcrx.c | linux/types.h      | PTR_ERR                  | 1         
| zcrx.c | linux/compiler.h   | READ_ONCE                | 1         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_recv_skb       | 4         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_unmap_area     | 2         
| zcrx.c | io_uring/zcrx.c   | __io_zcrx_unmap_area | 3         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_recv_frag      | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_recv            | 1         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_queue_cqe      | 3         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_put_niov_uref | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_map_area       | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_iov_to_area   | 5         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_iov_page       | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_get_rqe        | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_get_niov_uref | 3         
| zcrx.c | io_uring/zcrx.c   | __io_zcrx_get_free_niov | 3         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_scrub           | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_rqring_entries | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_ring_refill    | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_refill_slow    | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_drop_netdev    | 3         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_create_area    | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_copy_frag      | 2         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_copy_chunk     | 3         
| zcrx.c | io_uring/zcrx.c   | io_zcrx_alloc_fallback   | 2         
| zcrx.c | io_uring/zcrx.c   | io_pp_zc_release_netmem | 2         
| zcrx.c | io_uring/zcrx.c   | io_pp_zc_init            | 2         
| zcrx.c | io_uring/zcrx.c   | io_pp_zc_destroy         | 2         
| zcrx.c | io_uring/zcrx.c   | io_pp_zc_alloc_netmems  | 2         
| zcrx.c | io_uring/zcrx.c   | io_pp_uninstall           | 2         
| zcrx.c | io_uring/zcrx.c   | io_pp_nl_fill            | 2         
| zcrx.c | io_uring/zcrx.c   | io_get_user_counter      | 5         
| zcrx.c | io_uring/zcrx.c   | io_free_rbuf_ring        | 2         
| zcrx.c | io_uring/zcrx.c   | IO_DMA_ATTR               | 4         
| zcrx.c | io_uring/memmap.c | io_pin_pages              | 1         
| zcrx.c | io_uring/zcrx.c   | io_close_queue            | 3         
| zcrx.c | io_uring/rsrc.c   | io_buffer_validate        | 1         
| zcrx.c | io_uring/zcrx.c   | io_allocate_rbuf_ring    | 2         
| zcrx.c | io_uring/memmap.c | io_free_region            | 1         
| zcrx.c | io_uring/memmap.c | io_create_region_mmap_safe | 1         
| register.c | linux/uaccess.h  | copy_from_user    | 8         
| register.c | linux/uaccess.h  | copy_to_user      | 5         
| register.c | linux/uaccess.h  | u64_to_user_ptr  | 1         
| register.c | linux/compiler.h | READ_ONCE          | 7         
| register.c | linux/compiler.h | WRITE_ONCE         | 12        
| register.c | linux/compiler.h | unlikely            | 3         
| register.c | linux/kernel.h   | WARN_ON_ONCE      | 2         
| register.c | linux/kernel.h   | IS_ERR             | 2         
| register.c | linux/kernel.h   | PTR_ERR            | 2         
| register.c | linux/slab.h     | kzalloc             | 1         
| register.c | linux/slab.h     | kfree               | 2         
| register.c | linux/string.h   | memset              | 4         
| register.c | linux/string.h   | memchr_inv         | 3         
| register.c | linux/string.h   | memdup_user        | 1         
| register.c | linux/mutex.h    | mutex_lock         | 8         
| register.c | linux/mutex.h    | mutex_unlock       | 9         
| register.c | linux/mm.h       | PAGE_ALIGN         | 2         
| register.c | linux/refcount.h | refcount_inc       | 1         
| register.c | linux/spinlock.h | spin_lock          | 1         
| register.c | linux/spinlock.h | spin_unlock        | 1         
| register.c | linux/bitops.h   | test_bit           | 1         
| register.c | linux/bitops.h   | __set_bit        | 2         
| register.c | linux/cpumask.h  | alloc_cpumask_var | 1         
| register.c | linux/cpumask.h  | free_cpumask_var  | 2         
| register.c | linux/cpumask.h  | cpumask_clear      | 1         
| register.c | linux/cpumask.h  | cpumask_size       | 2         
| register.c | linux/cpumask.h  | cpumask_bits       | 1         
| register.c | linux/cred.h     | get_current_cred  | 1         
| register.c | linux/cred.h     | put_cred          | 2         
| register.c | linux/sched.h    | fget               | 1         
| register.c | linux/sched.h    | fput               | 3         
| register.c | linux/fs.h       | get_file          | 1         
| register.c | linux/mm.h       | array_size        | 3         
| register.c | linux/mm.h       | struct_size       | 1         
| register.c | linux/build_bug.h | BUILD_BUG_ON  | 1        
| register.c | linux/types.h    | XA_LIMIT          | 1         
| register.c | linux/xarray.h   | xa_alloc_cyclic  | 1         
| register.c | linux/xarray.h   | xa_erase          | 1         
| register.c | io_uring/register.c  | io_register_clock         | 2        
| register.c | io_uring/register.c  | io_register_resize_rings | 2        
| register.c | io_uring/register.c  | io_register_personality   | 2        
| register.c | io_uring/register.c  | io_register_mem_region   | 2         
| register.c | io_uring/register.c  | io_register_restrictions  | 2         
| register.c | io_uring/register.c  | io_register_enable_rings | 2         
| register.c | io_uring/register.c  | io_register_free_rings   | 6         
| register.c | io_uring/register.c  | io_register_iowq_aff     | 2         
| register.c | io_uring/register.c  | __io_register_iowq_aff | 3         
| register.c | io_uring/register.c  | io_register_iowq_max_workers | 2         
| register.c | io_uring/register.c  | io_probe                      | 2         
| register.c | io_uring/register.c  | io_parse_restrictions        | 2         
| register.c | io_uring/register.c  | io_uring_register_get_file | 2         
| register.c | io_uring/register.c  | io_uring_register_blind     | 2         
| register.c | io_uring/register.c  | __io_uring_register        | 2         
| register.c | io_uring/register.c  | SYSCALL_DEFINE4               | 1         
| register.c | io_uring/io_uring.c | io_is_uring_fops            | 1         
| register.c | io_uring/io_uring.c | io_uring_fill_params        | 1         
| register.c | io_uring/io_uring.c | io_activate_pollwq           | 1         
| register.c | io_uring/memmap.c    | io_create_region_mmap_safe | 3         
| register.c | io_uring/memmap.c    | io_free_region               | 3         
| register.c | io_uring/filetable.c | io_register_file_alloc_range | 1         
| register.c | io_uring/rsrc.c   | io_register_rsrc            | 2         
| register.c | io_uring/rsrc.c   | io_register_rsrc_update    | 2         
| register.c | io_uring/rsrc.c   | io_register_clone_buffers  | 1         
| register.c | io_uring/rsrc.c   | io_register_files_update   | 1         
| register.c | io_uring/rsrc.c   | io_sqe_buffers_register    | 1         
| register.c | io_uring/rsrc.c   | io_sqe_buffers_unregister  | 1         
| register.c | io_uring/rsrc.c   | io_sqe_files_register      | 1         
| register.c | io_uring/rsrc.c   | io_sqe_files_unregister    | 1         
| register.c | io_uring/sqpoll.c | io_put_sq_data             | 2         
| register.c | io_uring/sqpoll.c | io_sqpoll_wq_cpu_affinity | 1         
| register.c | io_uring/sqpoll.c | io_sq_thread_park          | 1         
| register.c | io_uring/sqpoll.c | io_sq_thread_unpark        | 1         
| register.c | io_uring/kbuf.c   | io_register_pbuf_ring      | 1         
| register.c | io_uring/kbuf.c   | io_register_pbuf_status    | 1         
| register.c | io_uring/kbuf.c   | io_unregister_pbuf_ring    | 1         
| register.c | io_uring/napi.c   | io_register_napi            | 1         
| register.c | io_uring/napi.c   | io_unregister_napi          | 1         
| register.c | io_uring/cancel.c | io_sync_cancel              | 1         
| register.c | io_uring/tctx.c   | io_ringfd_register          | 1         
| register.c | io_uring/tctx.c   | io_ringfd_unregister        | 1         
| register.c | io_uring/opdef.c  | io_uring_op_supported      | 1         
| register.c | io_uring/msg_ring.c | io_uring_sync_msg_ring | 1         
| register.c | io_uring/io-wq.c     | io_wq_cpu_affinity  | 1         
| register.c | io_uring/io-wq.c     | io_wq_max_workers   | 2   
| opdef.h | opdef.h | __OP_DECL  | 1          
| opdef.h | opdef.h | OP_DEF     | 33         
| opdef.h | opdef.h | OP_FEAT    | 3          
| opdef.h | opdef.h | OP_FEAT_MQ | 1            
| opdef.c | linux/kernel.h      | WARN_ON_ONCE       | 2  
| opdef.c | linux/kernel.h      | BUG_ON              | 2  
| opdef.c | linux/build_bug.h  | BUILD_BUG_ON       | 2  
| opdef.c | linux/array_size.h | ARRAY_SIZE          | 3  
| opdef.c | io_uring/opdef.c   | io_eopnotsupp_prep | 21 
| opdef.c | io_uring/opdef.c   | io_no_issue        | 2  
| opdef.c | io_uring/opdef.c   | io_uring_get_opcode   | 1  
| opdef.c | io_uring/opdef.c   | io_uring_op_supported | 1  
| opdef.c | io_uring/opdef.c   | io_uring_optable_init | 1  
| opdef.c | io_uring/opdef.c   | prep | 84 
| uring_cmd.h | linux/kernel.h | likely | 1         
| uring_cmd.h | linux/types.h  | container_of | 1         
| uring_cmd.h | uring_cmd.h | io_uring_cmd_complete_in_task | 1     
| uring_cmd.h | uring_cmd.h | io_uring_cmd_complete | 1         
| uring_cmd.h | uring_cmd.h | io_uring_cmd_done | 1         
| uring_cmd.h | uring_cmd.h | io_uring_cmd_pdu | 1         
| uring_cmd.h | uring_cmd.h | io_uring_cmd_pdu_init | 1        
| uring_cmd.c | linux/build_bug.h | BUILD_BUG_ON        | 1         
| uring_cmd.c | linux/kernel.h     | WARN_ON_ONCE        | 1         
| uring_cmd.c | linux/kernel.h     | offsetof              | 1         
| uring_cmd.c | linux/compiler.h   | READ_ONCE | 12        
| uring_cmd.c | linux/uaccess.h    | u64_to_user_ptr    | 2         
| uring_cmd.c | linux/slab.h       | kfree                 | 2         
| uring_cmd.c | linux/string.h     | memcpy                | 1         
| uring_cmd.c | linux/lockdep.h    | lockdep_assert_held | 1         
| uring_cmd.c | linux/smp.h        | smp_store_release   | 1         
| uring_cmd.c | linux/net.h        | KERNEL_SOCKPTR       | 1         
| uring_cmd.c | linux/net.h        | USER_SOCKPTR         | 2         
| uring_cmd.c | linux/security.h   | security_uring_cmd  | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_cmd_cache_free               | 1       
| uring_cmd.c | io_uring/uring_cmd.c | io_req_set_cqe32_extra         | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_req_uring_cleanup            | 4       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd                     | 25      
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_cleanup            | 1       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_del_cancelable    | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_getsockopt         | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_import_fixed      | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_import_fixed_vec | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_issue_blocking    | 1       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_mark_cancelable   | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_prep               | 1       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_prep_setup        | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_setsockopt         | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_sock               | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_work               | 2       
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_try_cancel_uring_cmd | 2       
| uring_cmd.c | io_uring/rsrc.c | EXPORT_SYMBOL_GPL  | 6         
| uring_cmd.c | io_uring/rsrc.c | io_import_reg_buf | 1         
| uring_cmd.c | io_uring/rsrc.c | io_import_reg_vec | 1         
| uring_cmd.c | io_uring/rsrc.c | io_prep_reg_iovec | 1         
| uring_cmd.c | io_uring/rsrc.c | io_vec_free        | 2         
| uring_cmd.c | io_uring/io_uring.c  | io_iopoll_req_issued          | 1         
| uring_cmd.c | io_uring/io_uring.c  | io_req_queue_iowq             | 1         
| uring_cmd.c | io_uring/io_uring.c  | __io_req_task_work_add     | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_op_supported         | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_optable_init | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_get_opcode | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_no_issue | 2         
| uring_cmd.c | io_uring/uring_cmd.c | io_eopnotsupp_prep | 21        
| uring_cmd.c | io_uring/uring_cmd.c | task_work_cb | 4         
| uring_cmd.c | io_uring/uring_cmd.c | req_set_fail | 2         
| uring_cmd.c | io_uring/uring_cmd.c | io_ring_submit_lock | 2         
| uring_cmd.c | io_uring/uring_cmd.c | io_ring_submit_unlock | 2         
| uring_cmd.c | io_uring/uring_cmd.c | io_should_terminate_tw | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_submit_flush_completions   | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_alloc_async_data    | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_uring_cmd_get_async_data | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_req_task_work_add | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_is_compat | 1         
| uring_cmd.c | io_uring/uring_cmd.c | io_req_set_res | 2         
| uring_cmd.c | io_uring/uring_cmd.c | io_kiocb_to_cmd | 6         
| uring_cmd.c | io_uring/uring_cmd.c | cmd_to_io_kiocb | 7    
| msg_ring.h | msg_ring.h | io_msg_send_fd | 1         
| msg_ring.h | msg_ring.h | io_msg_recv_fd | 1         
| msg_ring.h | msg_ring.h | io_msg_ring | 1         
| msg_ring.h | msg_ring.h | io_msg_install_fd | 1         
| msg_ring.h | msg_ring.h | io_msg_alloc_account | 1         
| msg_ring.h | msg_ring.h | io_msg_queue_fd | 1         
| msg_ring.h | msg_ring.h | io_msg_ring_account_init | 1         
| msg_ring.h | linux/types.h | container_of | 1       
| msg_ring.c | linux/kernel.h   | WARN_ON_ONCE  | 1         
| msg_ring.c | linux/compiler.h | unlikely        | 7         
| msg_ring.c | linux/compiler.h | READ_ONCE      | 8         
| msg_ring.c | linux/sched.h    | task_work_add | 1         
| msg_ring.c | linux/fs.h       | get_file       | 1         
| msg_ring.c | linux/fs.h       | fput            | 1         
| msg_ring.c | linux/fs.h       | fd_file        | 2         
| msg_ring.c | linux/fs.h       | fd_empty       | 1         
| msg_ring.c | linux/mutex.h    | mutex_lock     | 1         
| msg_ring.c | linux/mutex.h    | mutex_trylock  | 1         
| msg_ring.c | linux/mutex.h    | mutex_unlock   | 1         
| msg_ring.c | linux/spinlock.h | spin_trylock   | 2         
| msg_ring.c | linux/spinlock.h | spin_unlock    | 2         
| msg_ring.c | linux/percpu-refcount.h | percpu_ref_get | 1         
| msg_ring.c | linux/percpu-refcount.h | percpu_ref_put | 1         
| msg_ring.c | linux/slab.h | kmem_cache_alloc | 1         
| msg_ring.c | linux/slab.h | kmem_cache_free  | 2         
| msg_ring.c | io_uring/io_uring.c | io_add_aux_cqe   | 1         
| msg_ring.c | io_uring/io_uring.c | io_post_aux_cqe  | 2         
| msg_ring.c | io_uring/io_uring.c | io_is_uring_fops | 2         
| msg_ring.c | io_uring/io_uring.c | io_req_task_work_add_remote | 1         
| msg_ring.c | io_uring/msg_ring.c | io_lock_external_ctx | 3         
| msg_ring.c | io_uring/msg_ring.c | io_msg_data_remote   | 2         
| msg_ring.c | io_uring/msg_ring.c | io_msg_fd_remote     | 2         
| msg_ring.c | io_uring/msg_ring.c | io_msg_get_kiocb | 2         
| msg_ring.c | io_uring/msg_ring.c | io_msg_grab_file | 2         
| msg_ring.c | io_uring/msg_ring.c | io_msg_install_complete | 3         
| msg_ring.c | io_uring/msg_ring.c | io_msg_need_remote      | 3         
| msg_ring.c | io_uring/msg_ring.c | io_msg_remote_post      | 2         
| msg_ring.c | io_uring/msg_ring.c | io_msg_ring              | 1         
| msg_ring.c | io_uring/msg_ring.c | io_msg_ring_cleanup     | 1         
| msg_ring.c | io_uring/msg_ring.c | __io_msg_ring_data    | 3         
| msg_ring.c | io_uring/msg_ring.c | io_msg_ring_data        | 2         
| msg_ring.c | io_uring/msg_ring.c | __io_msg_ring_prep    | 3         
| msg_ring.c | io_uring/msg_ring.c | io_msg_ring_prep        | 1         
| msg_ring.c | io_uring/msg_ring.c | io_msg_send_fd          | 2         
| msg_ring.c | io_uring/msg_ring.c | io_msg_tw_complete      | 2         
| msg_ring.c | io_uring/msg_ring.c | io_msg_tw_fd_complete  | 2         
| msg_ring.c | io_uring/msg_ring.c | IORING_MSG_RING_MASK    | 2         
| msg_ring.c | io_uring/msg_ring.c | io_uring_sync_msg_ring | 1         
| msg_ring.c | io_uring/filtable.c | __io_fixed_fd_install | 1         
| msg_ring.c | io_uring/msg_ring.c | req_set_fail             | 2         
| msg_ring.c | io_uring/msg_ring.c | io_req_queue_tw_complete | 1         
| msg_ring.c | io_uring/msg_ring.c | io_req_set_res        | 2         
| msg_ring.c | io_uring/msg_ring.c | io_ring_submit_lock   | 1         
| msg_ring.c | io_uring/msg_ring.c | io_ring_submit_unlock | 1         
| msg_ring.c | io_uring/msg_ring.c | io_rsrc_node_lookup   | 1         
| msg_ring.c | io_uring/msg_ring.c | io_slot_file           | 1         
| msg_ring.c | io_uring/msg_ring.c | cmd_to_io_kiocb       | 1         
| msg_ring.c | io_uring/msg_ring.c | io_kiocb_to_cmd       | 8  
| eventfd.h  | linux/eventfd.h | eventfd_signal_mask | 1         
| eventfd.h  | linux/eventfd.h | eventfd_ctx_remove_wait_queue | 1   
| eventfd.h  | linux/eventfd.h | eventfd_ctx_read | 1         
| eventfd.h  | linux/eventfd.h | eventfd_ctx_write | 1         
| eventfd.h  | linux/file.h | fput | 1 
| eventfd.h  | linux/file.h | get_file | 1 
| eventfd.h  | linux/fs.h | anon_inode_getfile | 1   
| eventfd.c | linux/atomic.h     | atomic_fetch_or | 1         
| eventfd.c | linux/atomic.h     | atomic_set | 1        
| eventfd.c | linux/bitops.h     | BIT | 1        
| eventfd.c | linux/rcupdate.h   | call_rcu | 1        
| eventfd.c | linux/rcupdate.h   | call_rcu_hurry | 1         
| eventfd.c | linux/kernel.h     | container_of | 2        
| eventfd.c | linux/uaccess.h    | copy_from_user | 1         
| eventfd.c | linux/fs/eventfd.h | eventfd_ctx_fdget | 1         
| eventfd.c | linux/fs/eventfd.h | eventfd_ctx_put | 1         
| eventfd.c | linux/fs/eventfd.h | eventfd_signal_allowed | 1         
| eventfd.c | linux/fs/eventfd.h | eventfd_signal_mask | 2         
| eventfd.c | io_uring/eventfd.c | io_eventfd_flush_signal  | 1         
| eventfd.c | io_uring/eventfd.c | io_eventfd_free | 2         
| eventfd.c | io_uring/eventfd.c | io_eventfd_grab | 3         
| eventfd.c | io_uring/eventfd.c | io_eventfd_put | 4         
| eventfd.c | io_uring/eventfd.c | io_eventfd_register | 1         
| eventfd.c | io_uring/eventfd.c | io_eventfd_release | 3         
| eventfd.c | io_uring/eventfd.c | __io_eventfd_signal     | 3         
| eventfd.c | io_uring/eventfd.c | io_eventfd_signal | 1         
| eventfd.c | io_uring/eventfd.c | io_eventfd_trigger | 2         
| eventfd.c | io_uring/eventfd.c | io_eventfd_unregister     | 2         
| eventfd.c | io_uring/io-wq.c   | io_wq_current_is_worker | 1         
| eventfd.c | linux/kernel.h   | IS_ERR | 1         
| eventfd.c | linux/kernel.h   | PTR_ERR | 1         
| eventfd.c | linux/slab.h     | kfree | 2         
| eventfd.c | linux/slab.h     | kmalloc | 1         
| eventfd.c | linux/lockdep.h  | lockdep_is_held | 2         
| eventfd.c | linux/rcupdate.h | rcu_assign_pointer | 2         
| eventfd.c | linux/rcupdate.h | rcu_dereference | 2         
| eventfd.c | linux/rcupdate.h | rcu_dereference_protected | 2         
| eventfd.c | linux/rcupdate.h | rcu_read_lock | 2         
| eventfd.c | linux/rcupdate.h | rcu_read_unlock | 2         
| eventfd.c | linux/compiler.h | READ_ONCE | 1         
| eventfd.c | linux/refcount.h | refcount_dec_and_test    | 1         
| eventfd.c | linux/refcount.h | refcount_inc_not_zero    | 1         
| eventfd.c | linux/refcount.h | refcount_set               | 1         
| eventfd.c | linux/spinlock.h | spin_lock                  | 2         
| eventfd.c | linux/spinlock.h | spin_unlock                | 2     
| filetable.c | lib/bitmap.c | bitmap_free      | 1         
| filetable.c | lib/bitmap.c | bitmap_zalloc    | 1         
| filetable.c | include/linux/overflow.h   | check_add_overflow | 1         
| filetable.c | arch/x86/lib/usercopy_64.c | copy_from_user     | 1         
| filetable.c | lib/find_bit.c       | find_next_zero_bit  | 1         
| filetable.c | fs/file_table.c      | fput       | 2         
| filetable.c | io_uring/filetable.c | io_alloc_file_tables | 1         
| filetable.c | io_uring/filetable.c | io_file_bitmap_clear | 1         
| filetable.c | io_uring/filetable.c | io_file_bitmap_get   | 2         
| filetable.c | io_uring/filetable.c | io_file_bitmap_set   | 1         
| filetable.c | io_uring/filetable.c | io_file_table_set_alloc_range | 1         
| filetable.c | io_uring/filetable.c | __io_fixed_fd_install         | 2         
| filetable.c | io_uring/filetable.c | io_fixed_fd_install   | 2         
| filetable.c | io_uring/filetable.c | io_fixed_fd_remove    | 1         
| filetable.c | io_uring/filetable.c | io_fixed_file_set     | 1         
| filetable.c | io_uring/filetable.c | io_free_file_tables   | 1         
| filetable.c | io_uring/filetable.c | io_install_fixed_file | 2         
| filetable.c | io_uring/io_uring.c | io_is_uring_fops                | 1         
| filetable.c | io_uring/filetable.c | io_register_file_alloc_range   | 1         
| filetable.c | io_uring/filetable.c | io_reset_rsrc_node    | 2         
| filetable.c | io_uring/filetable.c | io_ring_submit_lock   | 1         
| filetable.c | io_uring/filetable.c | io_ring_submit_unlock | 1         
| filetable.c | io_uring/rsrc.c | io_rsrc_data_alloc    | 1         
| filetable.c | io_uring/rsrc.c | io_rsrc_data_free     | 2         
| filetable.c | io_uring/rsrc.c | io_rsrc_node_alloc    | 1         
| filetable.c | io_uring/rsrc.c | io_rsrc_node_lookup   | 1         
| filetable.c | include/linux/compiler_types.h| __must_hold | 1         
| filetable.c | include/linux/compiler.h       | unlikely | 3     
| truncate.c  | io_uring/truncate.c        | io_ftruncate      | 1  
| truncate.c  | io_uring/truncate.c        | io_ftruncate_prep | 1  
| truncate.c  | io_uring/io_uring.h        | io_kiocb_to_cmd   | 2  
| truncate.c  | io_uring/io_uring.h        | io_req_set_res    | 1  
| truncate.c  | /include/linux/compiler.h  | READ_ONCE         | 1  
| truncate.c  | /include/asm-generic/bug.h | WARN_ON_ONCE      | 1  
| truncate.c  | ../fs/internal.h           | do_ftruncate      | 1  
| io_uring.c | linux/string.h   | memset               | 6         
| io_uring.c | linux/slab.h     | kfree                | 12        
| io_uring.c | linux/uaccess.h  | copy_from_user     | 3         
| io_uring.c | linux/uaccess.h  | copy_to_user       | 1         
| io_uring.c | linux/bug.h      | BUG_ON              | 2         
| io_uring.c | linux/bug.h      | WARN_ON_ONCE       | 16        
| io_uring.c | linux/compiler.h | likely               | 6         
| io_uring.c | linux/compiler.h | unlikely             | 56        
| io_uring.c | linux/bitops.h   | set_bit             | 2         
| io_uring.c | linux/bitops.h   | clear_bit           | 2         
| io_uring.c | linux/atomic.h   | atomic_read         | 7         
| io_uring.c | linux/atomic.h   | atomic_set          | 6         
| io_uring.c | linux/atomic.h   | atomic_inc          | 2         
| io_uring.c | linux/atomic.h   | atomic_dec          | 2         
| io_uring.c | linux/atomic.h   | atomic_or           | 8         
| io_uring.c | linux/spinlock.h | spin_lock           | 12        
| io_uring.c | linux/spinlock.h | spin_unlock         | 14        
| io_uring.c | linux/mutex.h    | mutex_lock          | 21        
| io_uring.c | linux/mutex.h    | mutex_unlock        | 22        
| io_uring.c | linux/list.h     | list_add_tail      | 2         
| io_uring.c | linux/list.h     | list_del            | 1         
| io_uring.c | linux/list.h     | list_del_init      | 2         
| io_uring.c | linux/list.h     | list_empty          | 9         
| io_uring.c | linux/list.h     | list_first_entry   | 4         
| io_uring.c | linux/llist.h    | llist_add           | 2         
| io_uring.c | linux/llist.h    | llist_del_all      | 6         
| io_uring.c | linux/llist.h    | llist_empty         | 1         
| io_uring.c | linux/slab.h     | kmalloc              | 2         
| io_uring.c | linux/slab.h     | kvfree               | 2         
| io_uring.c | linux/slab.h     | kzalloc              | 1         
| io_uring.c | linux/sched.h    | schedule             | 3         
| io_uring.c | linux/sched.h    | wake_up             | 4         
| io_uring.c | linux/wait.h     | prepare_to_wait    | 2         
| io_uring.c | linux/wait.h     | finish_wait         | 2         
| io_uring.c | linux/uaccess.h  | unsafe_get_user    | 4         
| io_uring.c | asm/barrier.h    | smp_mb              | 4         
| io_uring.c | asm/barrier.h    | smp_rmb             | 2         
| io_uring.c | asm/barrier.h    | smp_wmb             | 2         
| io_uring.c | asm/cmpxchg.h    | try_cmpxchg         | 1         
| io_uring.c | linux/io_uring.h | io_uring_create    | 2         
| io_uring.c | linux/io_uring.h | io_uring_setup     | 3         
| io_uring.c | linux/io_uring.h | io_uring_init      | 2         
| io_uring.c | linux/io_uring.h | io_uring_poll      | 2         
| io_uring.c | linux/io_uring.h | io_uring_release   | 2         
| io_uring.c | linux/io_uring.h | io_uring_sanitise_params | 2        
| io_uring.c | linux/io_uring.h | io_uring_allowed | 2         
| io_uring.c | linux/io_uring.h | io_submit_sqe    | 2         
| io_uring.c | linux/io_uring.h | io_submit_sqes   | 2         
| io_uring.c | linux/io_uring.h | io_queue_sqe     | 4         
| io_uring.c | linux/io_uring.h | io_issue_sqe     | 4         
| io_uring.c | linux/io_uring.h | io_req_task_submit | 2         
| io_uring.c | linux/io_uring.h | io_req_post_cqe    | 1         
| io_uring.c | linux/io_uring.h | io_get_sqe          | 2         
| io_uring.c | linux/io_uring.h | io_file_get_flags  | 2         
| io_uring.c | linux/io_uring.h | io_file_get_fixed  | 2         
| io_uring.c | linux/io_uring.h | io_file_get_normal | 2         
| io_uring.c | linux/io_uring.h | io_put_task         | 2         
| io_uring.c | linux/io_uring.h | io_run_local_work  | 5         
| io_uring.c | linux/io_uring.h | io_match_task_safe | 3         
| io_uring.c | linux/io_uring.h | io_queue_iowq       | 6         
| io_uring.c | linux/io_uring.h | io_ring_ctx_alloc  | 2         
| io_uring.c | linux/io_uring.h | io_ring_ctx_free   | 2         
| io_uring.c | linux/io_uring.h | io_ring_exit_work  | 2 
| rw.h | linux/uio.h               | iov_iter_count     | 1         
| rw.h | fs/io_uring.c or internal | io_req_rw_complete | 1         
| rw.h | rw.h | io_req_map_rw      | 1         
| rw.h | rw.h | io_rw_init_file    | 1         
| rw.h | rw.h | io_rw_flags        | 1         
| rw.h | rw.h | io_rw_should_retry | 1         
| rw.h | rw.h | io_rw_retry        | 1      
| rw.c  | block/fops.c              | blkdev_write_iter | 1         
| rw.c  | io_uring/rw.c           | cmd_to_io_kiocb | 3         
| rw.c  | kernel/sched/completion.c | complete | 6        
| rw.c  | include/linux/kernel.h    | container_of | 5        
| rw.c  | lib/usercopy.c            | copy_from_user | 3         
| rw.c  | io_uring/rw.c           | DEFINE_IO_COMP_BATCH | 1         
| rw.c  | kernel/time/hrtimer.c     | destroy_hrtimer_on_stack | 1         
| rw.c  | fs/direct-io.c            | dio_complete | 4        
| rw.c  | fs/file_table.c          | file_inode | 3         
| rw.c  | mm/filemap.c          | __folio_lock_async | 1         
| rw.c  | block/blk-ioprio.c    | get_current_ioprio | 1         
| rw.c  | kernel/time/hrtimer.c | hrtimer_cancel | 1        
| rw.c  | kernel/time/hrtimer.c | hrtimer_set_expires | 1         
| rw.c  | kernel/time/hrtimer.c | hrtimer_setup_sleeper_on_stack | 1         
| rw.c  | kernel/time/hrtimer.c | hrtimer_sleeper_start_expires   | 1         
| rw.c  | fs/read_write.c          | __import_iovec | 1         
| rw.c  | io_uring/io_uring.c     | import_ubuf | 2         
| rw.c  | include/linux/list.h      | INIT_LIST_HEAD | 1         
| rw.c  | io_uring/alloc_cache.c  | io_alloc_cache_put | 1         
| rw.c  | io_uring/alloc_cache.c  | io_alloc_cache_vec_kasan | 1         
| rw.c  | rw.c | io_rw_init_file    | 1         
| rw.c  | rw.c | io_rw_should_retry | 1         
| rw.c  | fs/read_write.c | kiocb_set_rw_flags | 1         
| rw.c  | lib/iov_iter.c (or similar) | iov_iter_ubuf       | 1    
| memmap.c | mm/page_alloc.c | alloc_pages             | 1         
| memmap.c | mm/page_alloc.c | alloc_pages_bulk_node | 1         
| memmap.c | include/linux/overflow.h | check_add_overflow     | 3         
| memmap.c | include/linux/err.h    | ERR_PTR                 | 11        
| memmap.c | include/linux/mm.h     | get_order               | 1         
| memmap.c | mm/mmap.c              | get_unmapped_area      | 1         
| memmap.c | (local macro / helper) | guard                    | 4         
| memmap.c | io_uring/rsrc.c    | __io_account_mem           | 1        
| memmap.c | io_uring/rsrc.c    | io_check_coalesce_buffer    | 1       
| memmap.c | io_uring/memmap.c  | io_create_region             | 2      
| memmap.c | io_uring/memmap.c  | io_create_region_mmap_safe | 1       
| memmap.c | io_uring/memmap.c  | io_free_region | 2      
| memmap.c | io_uring/memmap.c  | io_mem_alloc_compound | 2       
| memmap.c | io_uring/memmap.c  | io_mmap_get_region    | 3       
| memmap.c | io_uring/kbuf.c    | io_pbuf_get_region          | 1       
| memmap.c | io_uring/memmap.c  | io_pin_pages                 | 2      
| memmap.c | io_uring/memmap.c  | io_region_allocate_pages    | 2       
| memmap.c | io_uring/memmap.c  | io_region_get_ptr           | 1       
| memmap.c | io_uring/memmap.c  | io_region_init_ptr          | 2       
| memmap.c | io_uring/memmap.c  | io_region_is_set            | 1       
| memmap.c | io_uring/memmap.c  | io_region_mmap               | 2      
| memmap.c | io_uring/memmap.c  | io_region_pin_pages         | 2       
| memmap.c | io_uring/memmap.c  | io_region_validate_mmap     | 2       
| memmap.c | io_uring/rsrc.c    | __io_unaccount_mem         | 1       
| memmap.c | io_uring/memmap.c  | io_uring_get_unmapped_area | 2       
| memmap.c | io_uring/memmap.c  | io_uring_mmap                | 2      
| memmap.c | io_uring/memmap.c  | io_uring_nommu_mmap_capabilities | 1        
| memmap.c | io_uring/memmap.c  | io_uring_validate_mmap_request   | 4        
| memmap.c | include/linux/err.h    | IS_ERR                    | 5         
| memmap.c | mm/nommu.c             | is_nommu_shared_mapping | 1         
| memmap.c | mm/slab_common.c      | kmalloc | 1         
| memmap.c | mm/util.c              | kvfree                  | 3         
| memmap.c | mm/util.c               | kvmalloc_array         | 2         
| memmap.c | kernel/locking/lockdep.c | lockdep_assert_held   | 1         
| memmap.c | lib/string.c            | memchr_inv             | 1         
| memmap.c | include/linux/string.h  | memcpy                  | 2         
| memmap.c | include/linux/string.h  | memset                  | 1         
| memmap.c | include/linux/minmax.h  | min                     | 1         
| memmap.c | mm/mmap.c               | mm_get_unmapped_area | 1         
| memmap.c | mm/highmem.c            | page_address           | 2         
| memmap.c | mm/gup.c                | pin_user_pages_fast  | 1         
| memmap.c | include/linux/err.h     | PTR_ERR                | 3         
| memmap.c | mm/swap.c               | release_pages          | 2         
| memmap.c | mm/gup.c                | unpin_user_pages      | 2         
| memmap.c | mm/vmalloc.c            | vmap                    | 2         
| memmap.c | mm/mmap.c               | vm_flags_set          | 1         
| memmap.c | mm/memory.c             | vm_insert_pages       | 1         
| memmap.c | mm/vmalloc.c            | vunmap                  | 2         
| memmap.c | include/asm-generic/bug.h | WARN_ON_ONCE          | 4    
| napi.h | napi.h | io_napi_id_hash | 1         
| napi.h | napi.h | io_napi_id_hash_unstable | 1         
| napi.h | napi.h | io_napi_timeout_ns | 1         
| napi.h | napi.h | io_napi_busy_loop_rcu | 1         
| napi.h | napi.h | io_napi_unregister | 1         
| napi.h | napi.h | io_napi_register | 1         
| napi.h | napi.h | io_register_napi | 1         
| napi.h | napi.h | io_unregister_napi | 1  
| napi.c | (standard C)            | bool | 13        
| napi.c | net/core/busy_poll.c   | busy_loop_current_time | 3         
| napi.c | lib/usercopy.c          | copy_from_user | 1         
| napi.c | lib/usercopy.c          | copy_to_user   | 2         
| napi.c | (local macro / helper)  | guard            | 4         
| napi.c | include/linux/hash.h    | HASH_BITS       | 2         
| napi.c | include/linux/rculist.h | hash_del_rcu   | 3         
| napi.c | include/linux/hash.h    | hash_min        | 2         
| napi.c | include/linux/rculist.h | hlist_add_tail_rcu | 1         
| napi.c | include/linux/list.h    | INIT_LIST_HEAD      | 1         
| napi.c | include/linux/rculist.h | INIT_LIST_HEAD_RCU | 1         
| napi.c | io_uring/napi.c | io_get_time                     | 1         
| napi.c | io_uring/napi.c | io_has_work                     | 1         
| napi.c | io_uring/napi.c | __io_napi_add_id             | 2         
| napi.c | io_uring/napi.c | io_napi_blocking_busy_loop    | 2         
| napi.c | io_uring/napi.c | __io_napi_busy_loop          | 2         
| napi.c | io_uring/napi.c | io_napi_busy_loop_should_end | 3         
| napi.c | io_uring/napi.c | io_napi_busy_loop_timeout     | 2         
| napi.c | io_uring/napi.c | __io_napi_del_id             | 2         
| napi.c | io_uring/napi.c | io_napi_free                    | 3         
| napi.c | io_uring/napi.c | io_napi_hash_find         | 4         
| napi.c | io_uring/napi.c | io_napi_init               | 2         
| napi.c | io_uring/napi.c | io_napi_register           | 1         
| napi.c | io_uring/napi.c | io_napi_register_napi     | 2         
| napi.c | io_uring/napi.c | __io_napi_remove_stale  | 2         
| napi.c | io_uring/napi.c | io_napi_remove_stale      | 3         
| napi.c | io_uring/napi.c | io_napi_sqpoll_busy_poll | 2         
| napi.c | io_uring/napi.c | io_napi_unregister         | 1         
| napi.c | io_uring/napi.c | io_register_napi           | 1         
| napi.c | io_uring/napi.c | io_should_wake           | 1         
| napi.c | io_uring/napi.c | io_unregister_napi       | 1       
| napi.c | mm/slab_common.c         | kfree         | 2        
| napi.c | include/linux/rcupdate.h  | kfree_rcu    | 4        
| napi.c | mm/slab_common.c         | kmalloc       | 1        
| napi.c | include/linux/ktime.h     | ktime_add    | 1        
| napi.c | include/linux/ktime.h     | ktime_after  | 1        
| napi.c | include/linux/ktime.h     | ktime_sub    | 1        
| napi.c | include/linux/ktime.h     | ktime_to_us | 2        
| napi.c | include/linux/rculist.h   | list_add_tail_rcu | 1        
| napi.c | include/linux/rculist.h   | list_del_rcu       | 3        
| napi.c | include/linux/rculist.h   | list_empty_careful | 1        
| napi.c | include/linux/list.h      | list_is_singular   | 1        
| napi.c | include/linux/minmax.h    | min_t               | 1        
| napi.c | net/core/dev.c            | napi_busy_loop_rcu | 2        
| napi.c | include/linux/netdevice.h | napi_id_valid      | 2        
| napi.c | io_uring/napi.c          | NAPI_TIMEOUT        | 3        
| napi.c | io_uring/napi.c          | net_to_ktime       | 3        
| napi.c | include/linux/ktime.h     | ns_to_ktime        | 2        
| napi.c | include/linux/compiler.h     | READ_ONCE       | 7       
| napi.c | (local macro / helper)       | scoped_guard    | 3        
| napi.c | include/linux/sched/signal.h | signal_pending  | 1       
| napi.c | include/linux/spinlock.h | spin_lock       | 1        
| napi.c | include/linux/spinlock.h | spin_lock_init | 1        
| napi.c | include/linux/spinlock.h | spin_unlock     | 2        
| napi.c | include/linux/jiffies.h  | time_after      | 2        
| napi.c | include/linux/compiler.h | unlikely         | 1        
| napi.c | include/linux/compiler.h | WRITE_ONCE      | 7  
| fdinfo.c | io_uring/fdinfo.c        | common_tracking_show_fdinfo | 3         
| fdinfo.c | kernel/user_namespace.c  | from_kgid_munged    | 5         
| fdinfo.c | kernel/user_namespace.c  | from_kuid_munged    | 4         
| fdinfo.c | kernel/sys.c  | getrusage           | 1         
| fdinfo.c | io_uring/io_uring.c | io_slot_file        | 1         
| fdinfo.c | io_uring/opdef.c | io_uring_get_opcode | 1         
| fdinfo.c | io_uring/fdinfo.c | io_uring_show_cred  | 2         
| fdinfo.c | io_uring/fdinfo.c | io_uring_show_fdinfo | 1        
| fdinfo.c | include/linux/minmax.h | min                 | 2         
| fdinfo.c | io_uring/fs.c | mode                | 4         
| fdinfo.c | kernel/locking/mutex.c | mutex_trylock       | 1         
| fdinfo.c | kernel/locking/mutex.c | mutex_unlock        | 1         
| fdinfo.c | io_uring/fdinfo.c | napi_show_fdinfo    | 3         
| fdinfo.c | include/linux/compiler.h | READ_ONCE | 6         
| fdinfo.c | fs/seq_file.c | seq_file_path       | 1         
| fdinfo.c | fs/seq_file.c | seq_printf          | 32        
| fdinfo.c | fs/seq_file.c | seq_putc            | 1         
| fdinfo.c | fs/seq_file.c | seq_put_decimal_ull | 9         
| fdinfo.c | fs/seq_file.c | seq_put_hex_ll      | 1         
| fdinfo.c | fs/seq_file.c | seq_puts            | 9         
| fdinfo.c | fs/seq_file.c | seq_user_ns         | 1         
| fdinfo.c | include/linux/spinlock.h | spin_lock         | 1         
| fdinfo.c | include/linux/spinlock.h | spin_unlock       | 1         
| fdinfo.c | kernel/task_work.c       | task_work_pending | 1         
| fdinfo.c | include/linux/xarray.h   | xa_empty          | 1  
| xattr.c | fs/xattr.c | file_getxattr | 1         
| xattr.c | fs/xattr.c | filename_getxattr | 1         
| xattr.c | fs/xattr.c | filename_setxattr | 1         
| xattr.c | fs/xattr.c | file_setxattr | 1         
| xattr.c | fs/namei.c | getname | 2        
| xattr.c | fs/xattr.c | import_xattr_name    | 1         
| xattr.c | io_uring/xattr.c | io_fgetxattr          | 1         
| xattr.c | io_uring/xattr.c | io_fgetxattr_prep    | 1         
| xattr.c | io_uring/xattr.c | io_fsetxattr          | 1         
| xattr.c | io_uring/xattr.c | io_fsetxattr_prep    | 1         
| xattr.c | io_uring/xattr.c | io_getxattr           | 1         
| xattr.c | io_uring/xattr.c | __io_getxattr_prep | 3         
| xattr.c | io_uring/xattr.c | io_getxattr_prep     | 1         
| xattr.c | io_uring/io_uring.c | io_kiocb_to_cmd     | 9         
| xattr.c | io_uring/io_uring.c | io_req_set_res      | 1         
| xattr.c | io_uring/xattr.c | io_setxattr           | 1         
| xattr.c | io_uring/xattr.c | __io_setxattr_prep | 3         
| xattr.c | io_uring/xattr.c | io_setxattr_prep | 1         
| xattr.c | io_uring/xattr.c | io_xattr_cleanup | 2         
| xattr.c | io_uring/xattr.c | io_xattr_finish  | 5         
| xattr.c | include/linux/err.h  | IS_ERR | 2         
| xattr.c | mm/slab_common.c    | kfree   | 3         
| xattr.c | mm/slab_common.c     | kmalloc | 2         
| xattr.c | mm/util.c             | kvfree | 1         
| xattr.c | include/linux/err.h   | PTR_ERR | 2         
| xattr.c | fs/namei.c                | putname | 1         
| xattr.c | include/linux/compiler.h  | READ_ONCE | 10        
| xattr.c | fs/xattr.c                | setxattr_copy | 1         
| xattr.c | include/linux/uaccess.h   | u64_to_user_ptr | 6         
| xattr.c | include/linux/compiler.h  | unlikely | 2         
| xattr.c | include/asm-generic/bug.h | WARN_ON_ONCE | 4  
| advise.h | linux/mm.h | madvise | 1         
| advise.h | linux/fs.h | fput | 1         
| advise.h | linux/file.h | get_file | 1         
| advise.h | linux/mman.h | do_madvise | 1      
| advise.c | io_uring/advise.c | io_fadvise | 1         
| advise.c | io_uring/advise.c | io_fadvise_prep | 1         
| advise.c | io_uring/advise.c | io_fadvise_force_async | 1       
| advise.c | io_uring/advise.c | io_madvise           | 1         
| advise.c | io_uring/advise.c | io_madvise_prep      | 1         
| advise.c | io_uring/io_uring.h | io_kiocb_to_cmd      | 4         
| advise.c | io_uring/io_uring.h | io_req_set_res       | 2         
| advise.c | /include/linux/compiler.h  | READ_ONCE    | 8         
| advise.c | io_uring/io_uring.h        | req_set_fail | 1         
| advise.c | /include/linux/fs.h        | vfs_fadvise  | 1         
| advise.c | /include/asm-generic/bug.h | WARN_ON_ONCE | 2         
| advise.c | /include/linux/mm.h        | do_madvise   | 1  
| epoll.h | linux/fs.h | get_file | 1         
| epoll.h | linux/fs.h | fput | 1         
| epoll.h | linux/eventpoll.h | epoll_ctl | 1         
| epoll.h | linux/eventpoll.h | epoll_create | 1         
| epoll.h | linux/eventpoll.h | epoll_file_register | 1         
| epoll.h | linux/eventpoll.h | epoll_file_unregister | 1         
| epoll.h | linux/file.h | anon_inode_getfile | 1         
| epoll.c | lib/usercopy.c | copy_from_user   | 1         
| epoll.c | fs/eventpoll.c | epoll_sendevents | 1         
| epoll.c | fs/eventpoll.c | ep_op_has_event  | 1         
| epoll.c | io_uring/epoll.c | io_epoll_ctl      | 1         
| epoll.c | io_uring/epoll.c | io_epoll_ctl_prep | 1         
| epoll.c | io_uring/epoll.c | io_epoll_wait     | 6         
| epoll.c | io_uring/epoll.c    | io_epoll_wait_prep | 1         
| epoll.c | io_uring/io_uring.c | io_kiocb_to_cmd    | 4         
| epoll.c | io_uring/io_uring.c | io_req_set_res     | 2         
| epoll.c | include/linux/compiler.h | READ_ONCE       | 6         
| epoll.c | io_uring/io_uring.c      | req_set_fail    | 2         
| epoll.c | include/linux/uaccess.h  | u64_to_user_ptr | 2   
| fs.h | fs.h | io_file_get_normal | 1         
| fs.h | fs.h | io_file_get_write  | 1         
| fs.h | fs.h | io_file_get_rw     | 1         
| fs.h | fs.h | io_file_need_ctx   | 1         
| fs.h | fs.h | io_file_can_poll   | 1         
| fs.h | fs.h | io_file_get_tx     | 1         
| fs.h | fs.h | io_file_need_iter  | 1         
| fs.h | linux/fs.h | vfs_iter_read | 1         
| fs.h | linux/fs.h | vfs_iter_write | 1         
| fs.h | linux/fs.h | fput | 1        |
| fs.h | linux/fs.h | get_file_rw_flags  | 1               
| fs.c | fs/namei.c | getname              | 7         
| fs.c | fs/namei.c | getname_uflags      | 1         
| fs.c | io_uring/io_uring.c | io_kiocb_to_cmd     | 14        
| fs.c | io_uring/fs.c | io_linkat           | 1         
| fs.c | io_uring/fs.c | io_linkat_prep      | 1         
| fs.c | io_uring/fs.c | io_link_cleanup     | 1         
| fs.c | io_uring/fs.c | io_mkdirat          | 1         
| fs.c | io_uring/fs.c | io_mkdirat_cleanup  | 1         
| fs.c | io_uring/fs.c | io_mkdirat_prep     | 1         
| fs.c | io_uring/fs.c | io_renameat         | 1         
| fs.c | io_uring/fs.c | io_renameat_cleanup | 1         
| fs.c | io_uring/fs.c | io_renameat_prep    | 1         
| fs.c | io_uring/io_uring.c | io_req_set_res      | 5         
| fs.c | io_uring/fs.c | io_symlinkat        | 1         
| fs.c | io_uring/fs.c | io_symlinkat_prep   | 1         
| fs.c | io_uring/fs.c | io_unlinkat         | 1         
| fs.c | io_uring/fs.c | io_unlinkat_cleanup | 1         
| fs.c | io_uring/fs.c | io_unlinkat_prep    | 1         
| fs.c | include/linux/err.h | IS_ERR  | 8         
| fs.c | include/linux/err.h | PTR_ERR | 8         
| fs.c | fs/namei.c          | putname | 9         
| fs.c | include/linux/compiler.h | READ_ONCE       | 19        
| fs.c | include/linux/uaccess.h  | u64_to_user_ptr | 8         
| fs.c | include/linux/compiler.h | unlikely        | 5         
| fs.c | include/asm-generic/bug.h| WARN_ON_ONCE    | 5      
| tctx.c | include/linux/nospec.h | array_index_nospec | 2         
| tctx.c | include/linux/atomic.h | atomic_set         | 2         
| tctx.c | kernel/sched/core.c | cond_resched       | 1         
| tctx.c | lib/usercopy.c | copy_from_user     | 2         
| tctx.c | lib/usercopy.c | copy_to_user       | 1         
| tctx.c | include/linux/err.h | ERR_PTR            | 1         
| tctx.c | fs/file.c | fget  | 1         
| tctx.c | fs/file.c | fput  | 5         
| tctx.c | include/linux/llist.h  | init_llist_head    | 1         
| tctx.c | kernel/task_work.c     | init_task_work     | 1         
| tctx.c | include/linux/wait.h   | init_waitqueue_head | 2         
| tctx.c | io_uring/tctx.c        | io_init_wq_offload  | 2         
| tctx.c | io_uring/io_uring.c    | io_is_uring_fops    | 1         
| tctx.c | io_uring/tctx.c | io_ring_add_registered_fd   | 2         
| tctx.c | io_uring/tctx.c | io_ring_add_registered_file | 2         
| tctx.c | io_uring/tctx.c | io_ringfd_register          | 1         
| tctx.c | io_uring/tctx.c | io_ringfd_unregister        | 1         
| tctx.c | io_uring/tctx.c | __io_uring_add_tctx_node    | 3         
| tctx.c | io_uring/tctx.c | __io_uring_add_tctx_node_from_submit | 1         
| tctx.c | io_uring/tctx.c | io_uring_alloc_task_context | 2         
| tctx.c | io_uring/tctx.c | io_uring_clean_tctx    | 1         
| tctx.c | io_uring/tctx.c | io_uring_del_tctx_node | 3         
| tctx.c | fs/io_uring.c   | io_uring_enter         | 1         
| tctx.c | io_uring/tctx.c | __io_uring_free        | 1         
| tctx.c | io_uring/io_uring.c| io_uring_try_cancel_iowq | 1         
| tctx.c | io_uring/tctx.c    | io_uring_unreg_ringfd    | 1         
| tctx.c | io_uring/io-wq.c   | io_wq_create             | 1         
| tctx.c | io_uring/io-wq.c   | io_wq_max_workers        | 1         
| tctx.c | io_uring/io-wq.c   | io_wq_put_and_exit       | 1         
| tctx.c | include/linux/err.h| IS_ERR  | 1         
| tctx.c | mm/slab_common.c   | kfree   | 5         
| tctx.c | mm/slab_common.c   | kmalloc | 1         
| tctx.c | mm/slab_common.c   | kzalloc | 2         
| tctx.c | include/linux/list.h | list_add   | 1         
| tctx.c | include/linux/list.h | list_del   | 1         
| tctx.c | include/linux/list.h | list_empty | 1         
| tctx.c | include/linux/minmax.h | min                    | 1         
| tctx.c | kernel/locking/mutex.c | mutex_lock             | 4         
| tctx.c | kernel/locking/mutex.c | mutex_unlock           | 5         
| tctx.c | kernel/smp.c           | num_online_cpus        | 1         
| tctx.c | lib/percpu_counter.c   | percpu_counter_destroy | 2         
| tctx.c | lib/percpu_counter.c   | percpu_counter_init    | 1         
| tctx.c | include/linux/err.h    | PTR_ERR      | 1         
| tctx.c | include/linux/refcount.h  | refcount_set | 1         
| tctx.c | include/linux/compiler.h  | unlikely     | 4         
| tctx.c | include/asm-generic/bug.h | WARN_ON_ONCE | 5         
| tctx.c | include/linux/xarray.h | xa_empty | 1         
| tctx.c | include/linux/xarray.h | xa_erase | 1         
| tctx.c | include/linux/xarray.h | xa_err   | 1         
| tctx.c | include/linux/xarray.h | xa_init  | 1         
| tctx.c | include/linux/xarray.h | xa_load  | 1         
| tctx.c | include/linux/xarray.h | xa_store | 2
| sqpoll.h | linux/sched.h (atau internal) | set_current_state | 1       
| sqpoll.h | linux/sched.h | schedule_timeout         | 1       
| sqpoll.h | linux/sched.h | __set_current_state      | 1       
| sqpoll.h | linux/sched.h | schedule                 | 1       
| sqpoll.h | linux/wait.h  | wait_event_interruptible | 1       
| sqpoll.h | sqpoll.h | io_sq_thread             | 1       
| sqpoll.h | sqpoll.h | io_sq_thread_acquire_mm  | 1       
| sqpoll.h | sqpoll.h | io_sq_thread_park        | 1       
| sqpoll.h | sqpoll.h | io_sq_thread_unpark      | 1
| refs.h | refs.h | io_file_assume_locked | 1         
| refs.h | refs.h | io_file_get           | 1         
| refs.h | refs.h | io_file_put           | 1         
| refs.h | refs.h | io_file_ref_get       | 1         
| refs.h | refs.h | io_file_ref_put       | 1         
| refs.h | refs.h | io_file_ref_swap      | 1         
| refs.h | refs.h | io_install_fixed_file | 1         
| refs.h | refs.h | io_file_bitmap_get    | 1         
| refs.h | refs.h | io_file_bitmap_set    | 1         
| refs.h | refs.h | io_fixed_fd_install   | 1         
| refs.h | linux/types.h | container_of   | 1     
| notif.h | notif.h | io_notify_send | 1         
| notif.h | notif.h | io_notify_remove_all | 1         
| notif.h | notif.h | io_notify_fail_all | 1         
| notif.h | notif.h | io_async_wake | 1         
| notif.h | notif.h | io_should_trigger_evfd | 1     
| statx.h | statx.h | io_statx | 1         
| statx.h | statx.h | io_statx_convert | 1         
| statx.h | statx.h | io_statx_get_dentry | 1       
| timeout.h | linux/time.h | jiffies | 1         
| timeout.h | linux/time.h | time_after | 1         
| timeout.h | timeout.h | io_schedule_timeout | 1         
| timeout.h | timeout.h | io_timeout_fn | 1         
| timeout.h | timeout.h | io_run_timeout | 1        
alloc_cache.h | /include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | arch/x86/include/asm/string_64.h| memset | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | alloc_cache.h | io_cache_alloc_new | 1
| | alloc_cache.h | io_alloc_cache_put | 1
| | linux/mm/slub.c | kfree | 1
| | alloc_cache.h | io_cache_alloc_new | 1
| | alloc_cache.h | io_alloc_cache_put | 1
| | linux/mm/slub.c | kfree | 1
io_uring.c | include/linux/syscalls.h | SYSCALL_DEFINE2 | 1
| | include/linux/syscalls.h | SYSCALL_DEFINE6 | 1
| | include/linux/err.h | IS_ERR | 2
| | include/linux/err.h | PTR_ERR | 2
| | include/linux/err.h | ERR_PTR | 2
| | include/linux/list.h | INIT_LIST_HEAD | 7
| | include/linux/list.h | LIST_HEAD | 14
| | include/linux/workqueue.h | INIT_WORK | 1
| | include/linux/workqueue.h | INIT_DELAYED_WORK | 1
| | include/linux/bug.h | WARN_ON_ONCE | 16
| | include/linux/bug.h | BUG_ON | 18
| | include/linux/bug.h | BUILD_BUG_ON | 16
| | include/linux/kernel.h | READ_ONCE | 34
| | include/linux/kernel.h | WRITE_ONCE | 11
| | include/linux/kernel.h | ALIGN | 4
| | include/linux/kernel.h | BIT | 45
| | include/linux/stat.h | S_ISREG | 1
| | include/linux/stat.h | S_ISBLK | 1
| | include/linux/mm.h | PAGE_ALIGN | 2
| | include/linux/wait.h | DEFINE_WAIT | 1
| | include/linux/jump_label.h | DEFINE_STATIC_KEY_FALSE | 1
| | io_uring.c | __io_cq_lock | 3
| | io_uring.c | __io_commit_cqring_flush | 1
| | io_uring.c | io_cqring_ev_events | 14
| | io_uring.c | io_uring_add_tctx_node | 2
io-wq.c | linux/refcount.h | refcount_inc_not_zero | 2
| | linux/refcount.h | refcount_dec_and_test | 2
| | linux/sched.h | wake_up_process | 2
| | linux/sched.h | set_task_comm | 1
| | linux/sched.h | signal_pending | 1
| | linux/sched.h | __set_current_state | 3
| | linux/atomic.h | atomic_inc | 4
| | linux/atomic.h | atomic_dec | 3
| | linux/atomic.h | atomic_dec_and_test | 2
| | linux/atomic.h | atomic_or | 2
| | linux/atomic.h | atomic_read | 2
| | linux/completion.h | init_completion | 1
| | linux/completion.h | wait_for_completion | 2
| | linux/completion.h | complete | 2
| | linux/slab.h | kzalloc | 1
| | linux/slab.h | kfree | 7
| | linux/slab.h | kmalloc | 1
| | linux/rcupdate.h | rcu_read_lock | 4
| | linux/rcupdate.h | rcu_read_unlock | 4
| | linux/cpumask.h | cpumask_test_cpu | 1
| | linux/cpumask.h | cpumask_set_cpu | 1
| | linux/cpumask.h | cpumask_clear_cpu | 1
| | linux/cpumask.h | cpumask_subset | 1
| | linux/cpumask.h | cpumask_copy | 2
| | linux/task_work.h | task_work_add | 1
| | linux/task_work.h | task_work_cancel_match | 2
| | linux/wait.h | __add_wait_queue | 1
| | linux/wait.h | wake_up | 2
| | linux/workqueue.h | schedule_delayed_work | 1
| | linux/workqueue.h | INIT_DELAYED_WORK | 1
| | linux/string.h | memset | 1
| | linux/signal.h | __set_notify_signal | 2
| | linux/sched/signal.h | fatal_signal_pending | 1
| | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/kernel.h | pr_warn_once | 1
| | linux/kernel.h | container_of | 10
| | linux/mm.h | kasan_mempool_unpoison_object | 1
| | io-wq.h | io_wq_current_is_worker | 1
| | io-wq.h | io_wq_work_match_all | 1
| | io-wq.h | io_wq_hash_work | 1
| | slist.h | wq_list_add_tail | 2
| | slist.h | wq_list_del | 3
| | slist.h | wq_list_for_each | 2
| | io_uring.h | create_io_thread | 2
| | io-wq.c (internal) | create_io_worker | 4
| | io-wq.c (internal) | io_wq_worker | 1
| | io-wq.c (internal) | io_wq_enqueue | 2
| | io-wq.c (internal) | io_wq_cancel_pending_work | 2
| | io-wq.c (internal) | io_worker_exit | 1
| | io-wq.c (internal) | io_worker_release | 5
| | io-wq.c (internal) | io_wq_dec_running | 3
| | io-wq.c (internal) | io_acct_run_queue | 2
io_uring.h | /linux/io_uring_types.h | WARN_ON_ONCE | 1
| | /linux/io_uring_types.h | __io_alloc_req_refill | 1
| | /linux/io_uring_types.h | __io_commit_cqring_flush | 2
| | /linux/io_uring_types.h | __io_req_task_work_add | 2
| | /linux/io_uring_types.h | __io_submit_flush_completions | 2
| | /linux/io_uring_types.h | __io_wake_waiters | 1
| | /linux/io_uring_types.h | __io_wake_waiters_func | 1
| | /linux/io_uring_types.h | _raw_spin_unlock_irqrestore | 1
| | /linux/io_uring_types.h | _raw_spin_unlock_irqsave | 1
| | /linux/io_uring_types.h | kfree | 1
| | /linux/io_uring_types.h | ktime_get | 1
| | /linux/io_uring_types.h | mlock | 1
| | /linux/io_uring_types.h | memset | 1
| | /linux/io_uring_types.h | memcpy | 1
| | /linux/io_uring_types.h | memcpy_fromio | 1
| | /linux/io_uring_types.h | memcpy_toio | 1
| | /linux/io_uring_types.h | min | 6
| | /linux/io_uring_types.h | mmap | 1
| | /linux/io_uring_types.h | mmaps_get | 1
| | /linux/io_uring_types.h | msleep | 1
| | /linux/io_uring_types.h | mutex_lock | 2
| | /linux/io_uring_types.h | mutex_unlock | 2
| | /linux/io_uring_types.h | ndelay | 1
| | /linux/io_uring_types.h | nf_unregister_net_hooks | 1
| | /linux/io_uring_types.h | op_get_async_ur | 1
| | /linux/io_uring_types.h | op_get_write_list | 1
| | /linux/io_uring_types.h | poll_schedule | 1
| | /linux/io_uring_types.h | pr_debug | 1
| | /linux/io_uring_types.h | pr_err | 1
| | /linux/io_uring_types.h | pr_info | 1
| | /linux/io_uring_types.h | pr_warn | 1
| | /linux/io_uring_types.h | putname | 1
| | /linux/io_uring_types.h | read_lock | 1
| | /linux/io_uring_types.h | read_unlock | 1
| | /linux/io_uring_types.h | register_mem_shard | 1
| | /linux/io_uring_types.h | reserve_page | 1
| | /linux/io_uring_types.h | return_on_error | 1
| | /linux/io_uring_types.h | tctx_task_work_run | 2
| | /linux/io_uring_types.h | trace_io_uring_complete | 1
| | /linux/io_uring_types.h | unlikely | 1
| | /linux/io_uring_types.h | wq_list_add_tail | 1
| | /linux/io_uring_types.h | wq_stack_extract | 1
sqpoll.c | linux/kernel.h | WARN_ON_ONCE | 4
| | linux/kernel.h | READ_ONCE | 1
| | linux/kernel.h | container_of | 1
| | linux/slab.h | kzalloc | 1
| | linux/slab.h | kfree | 2
| | linux/sched.h | wake_up_process | 2
| | linux/sched.h | set_task_comm | 1
| | linux/sched.h | signal_pending | 3
| | linux/sched.h | __set_current_state | 1
| | linux/refcount.h | refcount_dec_and_test | 1
| | linux/refcount.h | refcount_inc | 1
| | linux/atomic.h | atomic_inc | 1
| | linux/atomic.h | atomic_dec_return | 1
| | linux/atomic.h | atomic_andnot | 1
| | linux/atomic.h | atomic_or | 3
| | linux/completion.h | init_completion | 1
| | linux/completion.h | complete | 2
| | linux/wait.h | wait_event | 1
| | linux/wait.h | prepare_to_wait | 2
| | linux/wait.h | finish_wait | 2
| | linux/mutex.h | mutex_lock | 7
| | linux/mutex.h | mutex_unlock | 6
| | linux/list.h | list_for_each_entry | 4
| | linux/list.h | list_add | 1
| | linux/list.h | list_del_init | 1
| | linux/cpumask.h | cpumask_of | 1
| | linux/cpumask.h | cpumask_test_cpu | 1
| | linux/cred.h | override_creds | 1
| | linux/cred.h | revert_creds | 1
| | linux/security.h | security_uring_sqpoll | 1
| | linux/audit.h | audit_uring_entry | 1
| | linux/audit.h | audit_uring_exit | 1
| | uapi/linux/io_uring.h | struct io_uring_params | 2
| | io_uring.h | io_uring_alloc_task_context | 1
| | io_uring.h | io_uring_cancel_generic | 1
| | io_uring.h | io_run_task_work | 1
| | io_uring.h | create_io_thread | 1
| | napi.h | io_napi | 1
| | napi.h | io_napi_sqpoll_busy_poll | 1
| | sqpoll.c (internal) | io_sq_thread_unpark | 2
| | sqpoll.c (internal) | io_sq_thread_park | 3
| | sqpoll.c (internal) | io_sq_thread_stop | 1
| | sqpoll.c (internal) | io_put_sq_data | 1
| | sqpoll.c (internal) | io_sqd_update_thread_idle | 2
| | sqpoll.c (internal) | io_sq_thread_finish | 2
openclose.c | io_uring.h | io_kiocb_to_cmd | 1
| | linux/kernel.h | READ_ONCE | 3
| | linux/io_uring.h | u64_to_user_ptr | 1
| | linux/namei.h | getname | 1
| | linux/errno.h | PTR_ERR | 1
| | linux/io_uring.h | READ_ONCE | 1
| | linux/io_uring.h | io_kiocb_to_cmd | 1
| | linux/io_uring.h | io_uring_alloc_task_context | 1
| | linux/io_uring.h | io_uring_cancel_generic | 1
| | linux/io_uring.h | io_run_task_work | 1
| | linux/io_uring.h | create_io_thread | 1
| | napi.h | io_napi | 1
| | napi.h | io_napi_sqpoll_busy_poll | 1
| | sqpoll.c (internal) | io_sq_thread_unpark | 2
| | sqpoll.c (internal) | io_sq_thread_park | 3
| | sqpoll.c (internal) | io_sq_thread_stop | 1
| | sqpoll.c (internal) | io_put_sq_data | 1
| | sqpoll.c (internal) | io_sqd_update_thread_idle | 2
| | sqpoll.c (internal) | io_sq_thread_finish | 2
cancel.c | linux/kernel.h | WARN_ON_ONCE | 1
| | linux/io_uring.h | container_of | 1
| | linux/io_uring.h | io_cancel_req_match | 1
| | linux/io_uring.h | io_wq_cancel_cb | 1
| | linux/kernel.h | WARN_ON_ONCE | 1
| | linux/io_uring.h | io_async_cancel_one | 1
| | linux/io_uring.h | io_cancel_cb | 1
| | linux/io_uring.h | io_async_cancel_prep | 1
| | linux/list.h | list_for_each_entry | 1
| | linux/io_uring.h | io_async_cancel | 1
| | linux/kernel.h | __must_hold | 1
| | linux/kernel.h | bool | 1
| | linux/list.h | hlist_for_each_entry_safe | 1
slist.h | linux/io_uring_types.h | WRITE_ONCE | 3
| | linux/io_uring_types.h | INIT_WQ_LIST | 1
| | linux/io_uring_types.h | __wq_list_splice | 1
| | Unknown Library | wq_stack_extract | 1
| | Unknown Library | wq_next_work | 1
| | linux/io_uring_types.h | wq_list_for_each | 1
| | linux/io_uring_types.h | wq_list_for_each_resume | 1
| | linux/io_uring_types.h | wq_list_empty | 1
| | linux/io_uring_types.h | wq_list_add_after | 1
| | linux/io_uring_types.h | wq_list_add_tail | 1
| | linux/io_uring_types.h | wq_list_for_each_pos | 1
sync.c | linux/io_uring_types.h | io_sfr_prep | 1
| | linux/io_uring_types.h | io_sync_file_range | 1
| | linux/io_uring_types.h | io_fsync_prep | 1
| | linux/io_uring_types.h | io_fsync | 1
| | linux/io_uring_types.h | io_fallocate_prep | 1
| | linux/io_uring_types.h | io_fallocate | 1
| | linux/io_uring_types.h | io_kiocb_to_cmd | 2
| | linux/kernel.h | READ_ONCE | 9
net.h | Unknown Library | struct_group | 1
| | linux/io_uring_types.h | io_shutdown_prep | 1
| | linux/io_uring_types.h | io_shutdown | 1
| | linux/io_uring_types.h | io_sendmsg_recvmsg_cleanup | 1
| | linux/io_uring_types.h | io_sendmsg_prep | 1
| | linux/io_uring_types.h | io_sendmsg | 1
| | linux/io_uring_types.h | io_send | 1
| | linux/io_uring_types.h | io_recvmsg_prep | 1
| | linux/io_uring_types.h | io_recvmsg | 1
| | linux/io_uring_types.h | io_recv | 1
| | linux/io_uring_types.h | io_sendrecv_fail | 1
| | linux/io_uring_types.h | io_accept_prep | 1
| | linux/io_uring_types.h | io_accept | 1
| | linux/io_uring_types.h | io_socket_prep | 1
| | linux/io_uring_types.h | io_socket | 1
| | linux/io_uring_types.h | io_connect_prep | 1
| | linux/io_uring_types.h | io_connect | 1
| | linux/io_uring_types.h | io_send_zc | 1
| | linux/io_uring_types.h | io_sendmsg_zc | 1
| | linux/io_uring_types.h | io_send_zc_prep | 1
| | linux/io_uring_types.h | io_send_zc_cleanup | 1
| | linux/io_uring_types.h | io_bind_prep | 1
| | linux/io_uring_types.h | io_bind | 2
| | linux/io_uring_types.h | io_listen_prep | 1
| | linux/io_uring_types.h | io_listen | 1
| | linux/io_uring_types.h | io_netmsg_cache_free | 2
filetable.h | linux/io_uring_types.h | io_alloc_file_tables | 1
| | linux/io_uring_types.h | io_free_file_tables | 1
| | linux/io_uring_types.h | io_fixed_fd_remove | 1
| | linux/io_uring_types.h | io_file_get_flags | 2
| | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/bitmap.h | __clear_bit | 1
| | linux/bitmap.h | __set_bit | 1
| | linux/bitmap.h | io_file_bitmap_clear | 1
| | linux/bitmap.h | io_file_bitmap_set | 1
| | linux/bitmap.h | io_slot_flags | 1
| | linux/bitmap.h | io_slot_file | 1
memmap.h | Unknown Library | io_region_get_ptr | 1
| | Unknown Library | io_region_is_set | 1
| | linux/io_uring_types.h | io_pin_pages | 1
| | linux/io_uring_types.h | io_uring_nommu_mmap_capabilities | 1
| | linux/io_uring_types.h | io_uring_mmap | 1
| | linux/io_uring_types.h | io_free_region | 1
futex.h | linux/io_uring_types.h | io_futex_prep | 1
| | linux/io_uring_types.h | io_futexv_prep | 1
| | linux/io_uring_types.h | io_futex_wait | 1
| | linux/io_uring_types.h | io_futexv_wait | 1
| | linux/io_uring_types.h | io_futex_wake | 1
| | linux/io_uring_types.h | io_futex_cache_init | 2
| | linux/io_uring_types.h | io_futex_cache_free | 2
| | linux/io_uring_types.h | io_futex_cancel | 2
| | linux/io_uring_types.h | io_futex_remove_all | 2
sync.h | linux/io_uring_types.h | io_sfr_prep | 1
| | linux/io_uring_types.h | io_sync_file_range | 1
| | linux/io_uring_types.h | io_fsync_prep | 1
| | linux/io_uring_types.h | io_fsync | 1
| | linux/io_uring_types.h | io_fallocate | 1
| | linux/io_uring_types.h | io_fallocate_prep | 1
register.h | linux/io_uring_types.h | io_eventfd_unregister | 1
| | linux/io_uring_types.h | io_unregister_personality | 1
| | linux/io_uring_types.h | io_uring_register_get_file | 1
splice.h | linux/io_uring_types.h | io_tee_prep | 1
| | linux/io_uring_types.h | io_tee | 1
| | linux/io_uring_types.h | io_splice_cleanup | 1
| | linux/io_uring_types.h | io_splice_prep | 1
| | linux/io_uring_types.h | io_splice | 1
net.c | linux/io_uring_types.h | io_kiocb_to_cmd | 36
| | linux/kernel.h | READ_ONCE | 37
| | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/socket.h | sock_from_file | 11
| | linux/io_uring_types.h | io_req_set_res | 13
| | linux/io_uring_types.h | io_vec_free | 3
| | linux/io_uring_types.h | io_netmsg_iovec_free | 4
| | linux/io_uring_types.h | io_alloc_cache_vec_kasan | 1
| | linux/io_uring_types.h | io_uring_alloc_async_data | 1
| | linux/io_uring_types.h | io_is_compat | 1
| | linux/io_uring_types.h | io_vec_reset_iovec | 1
| | linux/io_uring_types.h | __get_compat_msghdr | 1
| | linux/compat.h | compat_ptr | 2
| | linux/uaccess.h | unsafe_get_user | 6
| | linux/uaccess.h | user_access_end | 2
| | linux/io_uring_types.h | io_compat_msg_copy_hdr | 1
| | linux/string.h | memset | 1
| | linux/io_uring_types.h | io_copy_msghdr_from_user | 1
| | linux/io_uring_types.h | __copy_msghdr | 1
| | linux/io_uring_types.h | u64_to_user_ptr | 8
| | linux/io_uring_types.h | move_addr_to_kernel | 3
| | linux/io_uring_types.h | io_msg_copy_hdr | 2
| | linux/io_uring_types.h | io_net_import_vec | 1
| | linux/io_uring_types.h | io_send_setup | 3
| | linux/io_uring_types.h | io_sendmsg_setup | 3
| | linux/io_uring_types.h | io_netmsg_recycle | 2
| | linux/kernel.h | min_t | 1
| | linux/kernel.h | while | 2
| | linux/io_uring_types.h | io_put_kbuf | 2
| | linux/io_uring_types.h | io_put_kbufs | 1
| | linux/io_uring_types.h | io_mshot_prep_retry | 2
| | linux/io_uring_types.h | iov_iter_count | 6
| | linux/io_uring_types.h | __sys_sendmsg_sock | 2
| | linux/io_uring_types.h | req_set_fail | 14
| | linux/io_uring_types.h | io_req_msg_cleanup | 6
| | linux/io_uring_types.h | io_buffers_select | 1
| | linux/io_uring_types.h | io_send_select_buffer | 1
| | linux/socket.h | sock_sendmsg | 2
| | linux/io_uring_types.h | io_msg_alloc_async | 5
| | linux/io_uring_types.h | io_recvmsg_copy_hdr | 1
| | linux/io_uring_types.h | io_recvmsg_prep_setup | 2
| | linux/socket.h | sock_recvmsg | 2
| | linux/io_uring_types.h | sizeof | 2
| | linux/io_uring_types.h | io_buffer_select | 2
| | linux/io_uring_types.h | io_recvmsg_prep_multishot | 1
| | linux/io_uring_types.h | io_kbuf_recycle | 5
| | linux/io_uring_types.h | iov_iter_ubuf | 1
| | linux/io_uring_types.h | min_not_zero | 1
| | linux/io_uring_types.h | io_buffers_peek | 1
| | linux/io_uring_types.h | io_recv_buf_select | 1
| | linux/io_uring_types.h | io_notif_flush | 3
| | linux/io_uring_types.h | io_alloc_notif | 1
| | linux/io_uring_types.h | io_notif_to_data | 1
| | linux/io_uring_types.h | io_notif_account_mem | 1
| | linux/io_uring_types.h | skb_zcopy_downgrade_managed | 1
| | linux/io_uring_types.h | zerocopy_fill_skb_from_iter | 2
| | linux/io_uring_types.h | skb_shinfo | 1
| | linux/io_uring_types.h | min | 1
| | linux/io_uring_types.h | mp_bvec_iter_bvec | 1
| | linux/io_uring_types.h | PAGE_ALIGN | 1
| | linux/io_uring_types.h | bvec_iter_advance_single | 1
| | linux/io_uring_types.h | io_send_zc_import | 2
| | linux/io_uring_types.h | rlimit | 2
| | linux/io_uring_types.h | __get_unused_fd_flags | 2
| | linux/io_uring_types.h | put_unused_fd | 2
| | linux/io_uring_types.h | PTR_ERR | 2
| | linux/io_uring_types.h | fd_install | 2
| | linux/io_uring_types.h | __sys_socket_file | 1
| | linux/io_uring_types.h | sock_error | 1
| | linux/io_uring_types.h | __sys_bind_socket | 1
| | linux/io_uring_types.h | __sys_listen_socket | 1
| | linux/slab.h | kfree | 1
| | linux/io_uring_types.h | io_shutdown_prep | 1
| | linux/io_uring_types.h | io_shutdown | 1
| | linux/io_uring_types.h | io_net_retry | 1
| | linux/io_uring_types.h | io_sendmsg_recvmsg_cleanup | 1
| | linux/io_uring_types.h | io_sendmsg_prep | 1
| | linux/io_uring_types.h | io_bundle_nbufs | 1
| | linux/io_uring_types.h | io_sendmsg | 1
| | linux/io_uring_types.h | io_send | 1
| | linux/io_uring_types.h | io_recvmsg_prep | 1
| | linux/io_uring_types.h | io_req_post_cqe | 2
| | linux/io_uring_types.h | io_recvmsg | 1
| | linux/io_uring_types.h | io_recv | 1
| | linux/io_uring_types.h | io_recvzc_prep | 1
| | linux/io_uring_types.h | io_recvzc | 1
| | linux/io_uring_types.h | io_send_zc_cleanup | 1
| | linux/io_uring_types.h | io_send_zc_prep | 1
| | linux/io_uring_types.h | io_send_zc | 1
| | linux/io_uring_types.h | io_sendmsg_zc | 1
| | linux/io_uring_types.h | io_sendrecv_fail | 1
| | linux/io_uring_types.h | io_accept_prep | 1
| | linux/io_uring_types.h | io_accept | 1
| | linux/io_uring_types.h | io_socket_prep | 1
| | linux/io_uring_types.h | io_socket | 1
| | linux/io_uring_types.h | io_connect_prep | 1
| | linux/io_uring_types.h | io_connect | 1
| | linux/io_uring_types.h | io_bind_prep | 1
| | linux/io_uring_types.h | io_bind | 1
| | linux/io_uring_types.h | io_listen_prep | 1
| | linux/io_uring_types.h | io_listen | 1
| | linux/io_uring_types.h | io_netmsg_cache_free | 1
poll.c | linux/io_uring_types.h | io_kiocb_to_cmd | 36
| | linux/kernel.h | READ_ONCE | 24
| | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/socket.h | sock_from_file | 10
| | linux/io_uring_types.h | io_req_set_res | 13
| | linux/io_uring_types.h | io_vec_free | 3
| | linux/io_uring_types.h | io_netmsg_iovec_free | 4
| | linux/io_uring_types.h | io_alloc_cache_vec_kasan | 1
| | linux/io_uring_types.h | io_uring_alloc_async_data | 1
| | linux/io_uring_types.h | io_is_compat | 1
| | linux/io_uring_types.h | io_vec_reset_iovec | 1
| | linux/io_uring_types.h | __get_compat_msghdr | 1
| | linux/compat.h | compat_ptr | 2
| | linux/uaccess.h | unsafe_get_user | 6
| | linux/uaccess.h | user_access_end | 2
| | linux/io_uring_types.h | io_compat_msg_copy_hdr | 1
| | linux/string.h | memset | 1
| | linux/io_uring_types.h | io_copy_msghdr_from_user | 1
| | linux/io_uring_types.h | __copy_msghdr | 1
| | linux/io_uring_types.h | u64_to_user_ptr | 8
| | linux/io_uring_types.h | move_addr_to_kernel | 3
| | linux/io_uring_types.h | io_msg_copy_hdr | 2
| | linux/io_uring_types.h | io_net_import_vec | 1
| | linux/io_uring_types.h | io_send_setup | 3
| | linux/io_uring_types.h | io_sendmsg_setup | 3
| | linux/io_uring_types.h | io_netmsg_recycle | 2
| | linux/kernel.h | min_t | 1
| | linux/kernel.h | while | 2
| | linux/io_uring_types.h | io_put_kbuf | 2
| | linux/io_uring_types.h | io_put_kbufs | 1
| | linux/io_uring_types.h | io_mshot_prep_retry | 2
| | linux/io_uring_types.h | iov_iter_count | 6
| | linux/io_uring_types.h | __sys_sendmsg_sock | 2
| | linux/io_uring_types.h | req_set_fail | 4
| | linux/io_uring_types.h | io_poll_issue | 1
| | linux/kernel.h | while | 1
| | linux/io_uring_types.h | io_napi_add | 2
| | linux/io_uring_types.h | io_poll_check_events | 2
| | linux/io_uring_types.h | io_kbuf_recycle | 3
| | linux/io_uring_types.h | io_poll_remove_entries | 5
| | linux/kernel.h | hash_del | 2
| | linux/io_uring_types.h | mangle_poll | 1
| | linux/io_uring_types.h | io_req_task_submit | 2
| | linux/io_uring_types.h | io_req_task_complete | 2
| | linux/io_uring_types.h | io_tw_lock | 1
| | linux/io_uring_types.h | io_req_defer_failed | 1
| | linux/io_uring_types.h | io_poll_mark_cancelled | 4
| | linux/io_uring_types.h | io_poll_execute | 3
| | linux/smp.h | smp_store_release | 1
| | linux/io_uring_types.h | wqe_to_req | 2
| | linux/kernel.h | container_of | 3
| | linux/io_uring_types.h | key_to_poll | 1
| | linux/io_uring_types.h | io_pollfree_wake | 2
| | linux/io_uring_types.h | io_poll_get_single | 2
| | linux/slab.h | kmalloc | 2
| | linux/io_uring_types.h | io_init_poll_iocb | 3
| | linux/slab.h | kfree | 2
| | linux/wait.h | add_wait_queue_exclusive | 1
| | linux/wait.h | add_wait_queue | 1
| | linux/io_uring_types.h | io_poll_get_ownership | 2
| | linux/io_uring_types.h | io_ring_submit_lock | 3
| | linux/io_uring_types.h | io_poll_req_insert | 2
| | linux/io_uring_types.h | io_ring_submit_unlock | 3
| | linux/list.h | INIT_HLIST_NODE | 1
| | linux/kernel.h | atomic_set | 1
| | linux/io_uring_types.h | io_poll_add_hash | 3
| | linux/io_uring_types.h | __io_queue_proc | 1
| | linux/io_uring_types.h | io_cache_alloc | 1
| | linux/io_uring_types.h | io_req_alloc_apoll | 1
| | linux/io_uring_types.h | __io_arm_poll_handler | 2
| | linux/io_uring_types.h | trace_io_uring_poll_arm | 1
| | linux/list.h | hlist_del_init | 1
| | linux/io_uring_types.h | io_poll_cancel_req | 3
| | linux/io_uring_types.h | io_poll_file_find | 1
| | linux/io_uring_types.h | io_poll_find | 2
| | linux/io_uring_types.h | __io_poll_cancel | 2
| | linux/kernel.h | READ_ONCE | 5
| | linux/io_uring_types.h | swahw32 | 1
| | linux/io_uring_types.h | io_poll_parse_events | 2
| | linux/io_uring_types.h | io_poll_disarm | 2
| | linux/io_uring_types.h | io_poll_add | 2
| | linux/io_uring_types.h | io_req_task_work_add | 1
| | linux/io_uring_types.h | wqe_is_double | 1
| | linux/io_uring_types.h | io_poll_get_double | 1
| | linux/io_uring_types.h | io_poll_task_func | 1
| | linux/io_uring_types.h | io_poll_double_prepare | 1
| | linux/io_uring_types.h | io_poll_can_finish_inline | 1
| | linux/io_uring_types.h | io_arm_poll_handler | 1
| | linux/io_uring_types.h | for | 2
| | linux/list.h | hlist_for_each_entry_safe | 1
| | linux/list.h | hlist_for_each_entry | 2
| | linux/io_uring_types.h | io_poll_remove_prep | 1
| | linux/io_uring_types.h | io_poll_add_prep | 1
| | linux/io_uring_types.h | io_poll_remove | 1
kbuf.c | Unknown Library | io_kbuf_inc_commit | 2
| | Unknown Library | io_kbuf_drop_legacy | 2
| | Unknown Library | io_kbuf_recycle_legacy | 1
| | Unknown Library | io_kbuf_alloc_commit | 1
| | Unknown Library | io_ring_head_to_buf | 1
| | linux/kernel.h | min_t | 3
| | Unknown Library | lockdep_assert_held | 6
| | linux/xa.h | xa_load | 2
| | Unknown Library | guard | 1
| | Unknown Library | xa_err | 1
| | linux/slab.h | kfree | 6
| | linux/io_uring_types.h | io_ring_submit_lock | 5
| | linux/io_uring_types.h | io_buffer_get_list | 10
| | linux/list.h | list_add | 1
| | linux/io_uring_types.h | io_ring_submit_unlock | 5
| | linux/list.h | list_first_entry | 2
| | linux/list.h | list_del | 2
| | linux/io_uring_types.h | u64_to_user_ptr | 3
| | linux/io_uring_types.h | io_provided_buffer_select | 2
| | linux/smp.h | smp_load_acquire | 2
| | linux/io_uring_types.h | io_kbuf_commit | 3
| | linux/io_uring_types.h | io_ring_buffer_select | 1
| | linux/kernel.h | READ_ONCE | 8
| | linux/io_uring_types.h | min_not_zero | 1
| | linux/slab.h | kmalloc_array | 1
| | linux/kernel.h | while | 4
| | linux/io_uring_types.h | io_ring_buffers_peek | 2
| | linux/io_uring_types.h | io_provided_buffers_select | 2
| | Unknown Library | io_kbuf_drop_legacy | 2
| | linux/io_uring_types.h | io_free_region | 2
| | linux/list.h | INIT_LIST_HEAD | 2
| | linux/sched.h | cond_resched | 2
| | linux/io_uring_types.h | __io_remove_buffers | 2
| | linux/xa.h | xa_find | 1
| | linux/xa.h | xa_erase | 2
| | linux/io_uring_types.h | io_put_bl | 4
| | linux/kernel.h | WARN_ON_ONCE | 1
| | linux/io_uring_types.h | io_kiocb_to_cmd | 4
| | linux/string.h | memset | 2
| | linux/io_uring_types.h | req_set_fail | 2
| | linux/io_uring_types.h | io_req_set_res | 2
| | linux/slab.h | kmalloc | 1
| | linux/list.h | list_add_tail | 1
| | linux/slab.h | kzalloc | 2
| | linux/io_uring_types.h | io_buffer_add_list | 3
| | linux/io_uring_types.h | io_add_buffers | 1
| | linux/io_uring_types.h | io_destroy_bl | 2
| | linux/io_uring_types.h | flex_array_size | 1
| | linux/io_uring_types.h | PAGE_ALIGN | 1
| | linux/io_uring_types.h | io_create_region_mmap_safe | 1
| | linux/io_uring_types.h | io_region_get_ptr | 1
| | linux/kernel.h | for | 2
| | linux/io_uring_types.h | io_kbuf_recycle_legacy | 1
| | linux/io_uring_types.h | io_buffers_peek | 1
| | linux/io_uring_types.h | __io_put_kbuf_ring | 1
| | linux/io_uring_types.h | __io_put_kbufs | 1
| | linux/io_uring_types.h | io_destroy_buffers | 1
| | Unknown Library | scoped_guard | 1
| | linux/io_uring_types.h | io_remove_buffers_prep | 1
| | linux/io_uring_types.h | io_remove_buffers | 1
| | linux/io_uring_types.h | io_provide_buffers_prep | 1
| | linux/io_uring_types.h | io_provide_buffers | 1
| | linux/io_uring_types.h | io_register_pbuf_ring | 1
| | linux/io_uring_types.h | io_unregister_pbuf_ring | 1
| | linux/io_uring_types.h | io_register_pbuf_status | 1
timeout.c | linux/io_uring_types.h | io_kiocb_to_cmd | 14
| | linux/io_uring_types.h | io_queue_next | 1
| | linux/io_uring_types.h | io_free_req | 1
| | linux/io_uring_types.h | io_timeout_fn | 2
| | linux/kernel.h | raw_spin_lock_irq | 8
| | linux/list.h | list_add | 2
| | linux/hrtimer.h | hrtimer_start | 4
| | linux/kernel.h | raw_spin_unlock_irq | 8
| | linux/io_uring_types.h | io_req_task_complete | 4
| | linux/list.h | list_first_entry | 1
| | linux/list.h | list_del_init | 3
| | linux/io_uring_types.h | cmd_to_io_kiocb | 6
| | linux/io_uring_types.h | req_set_fail | 3
| | linux/io_uring_types.h | io_req_queue_tw_complete | 3
| | linux/atomic.h | atomic_read | 3
| | linux/list.h | list_move_tail | 1
| | linux/list.h | LIST_HEAD | 2
| | linux/io_uring_types.h | io_kill_timeout | 2
| | linux/io_uring_types.h | io_flush_killed_timeouts | 3
| | linux/io_uring_types.h | io_tw_lock | 1
| | linux/io_uring_types.h | io_req_set_res | 5
| | linux/tracepoint.h | trace_io_uring_fail_link | 1
| | linux/io_uring_types.h | io_req_task_work_add | 3
| | linux/io_uring_types.h | io_remove_next_linked | 4
| | linux/io_uring_types.h | io_disarm_linked_timeout | 1
| | linux/io_uring_types.h | io_fail_links | 1
| | linux/list.h | list_del | 2
| | linux/kernel.h | raw_spin_lock_irqsave | 2
| | linux/kernel.h | raw_spin_unlock_irqrestore | 2
| | linux/err.h | ERR_PTR | 2
| | linux/io_uring_types.h | io_timeout_extract | 2
| | linux/err.h | PTR_ERR | 2
| | linux/io_uring_types.h | io_req_task_queue_fail | 1
| | linux/io_uring_types.h | io_try_cancel | 1
| | linux/io_uring_types.h | io_put_req | 3
| | linux/kernel.h | WARN_ON_ONCE | 1
| | linux/hrtimer.h | htimer_setup | 3
| | linux/list.h | list_add_tail | 2
| | linux/kernel.h | READ_ONCE | 4
| | linux/spinlock.h | spin_lock | 2
| | linux/io_uring_types.h | io_timeout_cancel | 1
| | linux/spinlock.h | spin_unlock | 2
| | linux/io_uring_types.h | io_translate_timeout_mode | 3
| | linux/io_uring_types.h | io_linked_timeout_update | 1
| | linux/io_uring_types.h | io_timeout_update | 1
| | linux/list.h | INIT_LIST_HEAD | 1
| | linux/io_uring_types.h | io_uring_alloc_async_data | 1
| | linux/io_uring_types.h | __io_timeout_prep | 2
| | linux/io_uring_types.h | data_race | 1
| | linux/list.h | list_entry | 1
| | linux/io_uring_types.h | io_is_timeout_noseq | 1
| | linux/kernel.h | if | 19
| | linux/io_uring_types.h | io_timeout_complete | 1
| | linux/kernel.h | while | 3
| | linux/io_uring_types.h | __must_hold | 9
| | linux/io_uring_types.h | io_flush_timeouts | 1
| | linux/list.h | list_for_each_entry_safe | 2
| | linux/io_uring_types.h | io_req_tw_fail_links | 1
| | linux/list.h | list_for_each_entry | 2
| | linux/io_uring_types.h | io_req_task_link_timeout | 1
| | linux/io_uring_types.h | io_link_timeout_fn | 1
| | linux/io_uring_types.h | io_timeout_get_clock | 1
| | linux/kernel.h | switch | 1
| | linux/io_uring_types.h | io_timeout_remove_prep | 1
| | linux/io_uring_types.h | io_timeout_remove | 1
| | linux/io_uring_types.h | io_timeout_prep | 1
| | linux/io_uring_types.h | io_link_timeout_prep | 1
| | linux/io_uring_types.h | io_timeout | 1
| | linux/list.h | list_for_each_prev | 1
| | linux/io_uring_types.h | io_queue_linked_timeout | 1
| | linux/io_uring_types.h | io_for_each_link | 1
tctx.h | linux/io_uring_types.h  | io_uring_del_tctx_node | 1
| | linux/io_uring_types.h | __io_uring_add_tctx_node | 1
| | linux/io_uring_types.h | __io_uring_add_tctx_node_from_submit | 2
| | linux/io_uring_types.h | io_uring_clean_tctx | 1
| | linux/io_uring_types.h | io_uring_unreg_ringfd | 1
futex.c | linux/io_uring_types.h | sizeof | 2
| | linux/io_uring_types.h | io_alloc_cache_free | 1
| | linux/list.h | hlist_del_init | 2
| | linux/io_uring_types.h | io_req_task_complete | 2
| | linux/io_uring_types.h | io_tw_lock | 4
| | linux/io_uring_types.h | io_cache_free | 2
| | linux/io_uring_types.h | __io_futex_complete | 4
| | linux/io_uring_types.h | io_kiocb_to_cmd | 8
| | linux/io_uring_types.h | futex_unqueue_multiple | 1
| | linux/io_uring_types.h | io_req_set_res | 8
| | linux/slab.h | kfree | 8
| | linux/io_uring_types.h | io_req_task_work_add | 3
| | linux/io_uring_types.h | io_cancel_remove | 1
| | linux/io_uring_types.h | io_cancel_remove_all | 1
| | linux/io_uring_types.h | u64_to_user_ptr | 1
| | linux/kernel.h | READ_ONCE | 6
| | linux/io_uring_types.h | futex2_to_flags | 1
| | linux/slab.h | kcalloc | 1
| | linux/kernel.h | container_of | 1
| | linux/io_uring_types.h | io_ring_submit_lock | 1
| | linux/io_uring_types.h | futex_wait_multiple_setup | 1
| | linux/io_uring_types.h | io_ring_submit_unlock | 2
| | linux/io_uring_types.h | req_set_fail | 3
| | linux/sched.h | __set_current_state | 2
| | linux/list.h | hlist_add_head | 2
| | linux/io_uring_types.h | io_cache_alloc | 1
| | linux/io_uring_types.h | futex_queue | 1
| | linux/io_uring_types.h | return io_cancel_remove | 1
| | linux/io_uring_types.h | return io_cancel_remove_all | 1
waitid.c | Unknown Library | io_waitid_cb | 1
| | linux/kernel.h | put_pid | 2
| | linux/slab.h | kfree | 2
| | linux/uaccess.h | unsafe_put_user | 24
| | linux/io_uring_types.h | io_waitid_free | 2
| | linux/io_uring_types.h | io_waitid_compat_copy_si | 1
| | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/kernel.h | lockdep_assert_held | 2
| | linux/list.h | hlist_del_init | 4
| | linux/io_uring_types.h | io_waitid_finish | 4
| | linux/io_uring_types.h | req_set_fail | 4
| | linux/io_uring_types.h | io_req_set_res | 4
| | linux/atomic.h | atomic_or | 2
| | linux/spinlock.h | spin_lock_irq | 2
| | linux/list.h | list_del_init | 4
| | linux/spinlock.h | spin_unlock_irq | 2
| | linux/io_uring_types.h | io_waitid_complete | 4
| | linux/io_uring_types.h | io_req_queue_tw_complete | 2
| | linux/io_uring_types.h | io_cancel_remove | 1
| | linux/io_uring_types.h | io_cancel_remove_all | 1
| | linux/io_uring_types.h | io_req_task_work_add | 4
| | linux/wait.h | remove_wait_queue | 6
| | linux/io_uring_types.h | io_tw_lock | 2
| | linux/sched.h | __do_wait | 6
| | linux/wait.h | add_wait_queue | 4
| | linux/io_uring_types.h | io_waitid_drop_issue_ref | 2
| | linux/io_uring_types.h | io_req_task_complete | 2
| | linux/kernel.h | container_of | 4
| | linux/io_uring_types.h | io_uring_alloc_async_data | 2
| | linux/kernel.h | READ_ONCE | 6
| | linux/io_uring_types.h | u64_to_user_ptr | 2
| | linux/atomic.h | atomic_set | 2
| | linux/io_uring_types.h | io_ring_submit_lock | 2
| | linux/list.h | hlist_add_head | 2
| | linux/wait.h | init_waitqueue_func_entry | 2
| | linux/io_uring_types.h | io_ring_submit_unlock | 6
| | linux/io_uring_types.h | void io_waitid_cb | 1
| | linux/io_uring_types.h | return io_waitid_compat_copy_si | 1
| | linux/io_uring_types.h | return io_cancel_remove | 1
| | linux/io_uring_types.h | return io_cancel_remove_all | 1
splice.c | linux/io_uring_types.h | io_kiocb_to_cmd | 6
| | linux/io_uring_types.h | READ_ONCE | 7
| | Unknown Library | __io_splice_prep | 2
| | Unknown Library | io_put_rsrc_node | 2
| | Unknown Library | io_file_get_normal | 1
| | linux/io_uring_types.h | io_ring_submit_lock | 2
| | Unknown Library | io_rsrc_node_lookup | 1
| | Unknown Library | io_slot_file | 1
| | linux/io_uring_types.h | io_ring_submit_unlock | 2
| | linux/kernel.h | WARN_ON_ONCE | 4
| | linux/io_uring_types.h | io_splice_get_file | 2
| | Unknown Library | do_tee | 1
| | linux/fs.h | fput | 2
| | linux/io_uring_types.h | req_set_fail | 2
| | linux/io_uring_types.h | io_req_set_res | 4
| | Unknown Library | do_splice | 2
| | Unknown Library | return __io_splice_prep | 2
| | Unknown Library | return io_file_get_normal | 1
kbuf.h | linux/io_uring_types.h | io_buffers_peek | 1
| | linux/io_uring_types.h | io_destroy_buffers | 1
| | linux/io_uring_types.h | io_remove_buffers_prep | 1
| | linux/io_uring_types.h | io_remove_buffers | 1
| | linux/io_uring_types.h | io_provide_buffers_prep | 1
| | linux/io_uring_types.h | io_provide_buffers | 1
| | linux/io_uring_types.h | io_select_buffers | 1
| | linux/io_uring_types.h | io_buffer_list_alloc | 1
| | linux/io_uring_types.h | io_buffer_add_list | 1
| | linux/io_uring_types.h | io_cache_alloc | 1
| | linux/io_uring_types.h | io_cache_free | 1
| | linux/io_uring_types.h | io_req_task_complete | 1
| | linux/io_uring_types.h | io_req_set_res | 1
| | linux/io_uring_types.h | io_tw_lock | 1
| | linux/io_uring_types.h | io_buffers_push | 1
| | linux/io_uring_types.h | io_buffer_list_free | 1
kbuf.h | /uapi/linux/io_uring.h | __io_put_kbufs | 3
| | /linux/io_uring_types.h | io_buffer_select | 1
| | /linux/io_uring_types.h | io_buffers_peek | 1
| | /linux/io_uring_types.h | io_buffers_select | 1
| | /linux/io_uring_types.h | io_destroy_buffers | 1
| | /linux/io_uring_types.h | io_kbuf_commit | 1
| | /linux/io_uring_types.h | io_kbuf_drop_legacy | 1
| | /linux/io_uring_types.h | io_kbuf_recycle_legacy | 2
| | /linux/io_uring_types.h | io_kbuf_recycle_ring | 1
| | /linux/io_uring_types.h | io_pbuf_get_region | 1
| | /linux/io_uring_types.h | io_provide_buffers | 2
| | /linux/io_uring_types.h | io_provide_buffers_prep | 1
| | /linux/io_uring_types.h | io_register_pbuf_ring | 1
| | /linux/io_uring_types.h | io_register_pbuf_status | 1
| | /linux/io_uring_types.h | io_remove_buffers | 1
| | /linux/io_uring_types.h | io_remove_buffers_prep | 1
| | /linux/io_uring_types.h | io_unregister_pbuf_ring | 1
notif.c | /linux/kernel.h | WRITE_ONCE | 2
| | /linux/io_uring.h | __io_req_task_work_add | 1
| | /linux/io_uring.h | __io_unaccount_mem | 1
| | /linux/io_uring.h | cmd_to_io_kiocb | 4
| | /linux/io_uring.h | container_of | 3
| | /linux/io_uring.h | io_get_task_refs | 1
| | /linux/io_uring.h | io_notif_to_data | 2
| | /linux/io_uring.h | io_req_task_complete | 1
| | /linux/io_uring.h | io_tx_ubuf_complete | 1
| | /linux/net.h | net_zcopy_get | 2
| | /linux/refcount.h | refcount_set | 1
| | /linux/net.h | skb_zcopy | 1
| | /linux/net.h | skb_zcopy_init | 1
nop.c | /uapi/linux/io_uring.h | READ_ONCE | 4
| | /linux/io_uring.h | io_file_get_fixed | 1
| | /linux/io_uring.h | io_file_get_normal | 1
| | /linux/io_uring.h | io_kiocb_to_cmd | 2
| | /linux/io_uring.h | io_req_set_res | 1
| | /linux/io_uring.h | req_set_fail | 1
statx.c | /uapi/linux/io_uring.h | PTR_ERR | 1
| | /uapi/linux/io_uring.h | READ_ONCE | 3
| | /linux/kernel.h | WARN_ON_ONCE | 1
| | /linux/io_uring.h | do_statx | 1
| | /linux/io_uring.h | getname_uflags | 1
| | /linux/io_uring.h | io_kiocb_to_cmd | 3
| | /linux/io_uring.h | io_req_set_res | 1
| | /linux/io_uring.h | putname | 1
alloc_cache.h | /linux/io_uring_types.h | io_alloc_cache_get | 1
| | /linux/io_uring_types.h | io_alloc_cache_init | 1
| | /linux/io_uring_types.h | io_cache_alloc_new | 2
| | /include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | linux/mm/slub.c | kfree | 1
| | arch/x86/include/asm/string_64.h | memset | 1
poll.h | /linux/io_uring_types.h | atomic_inc | 1
| | /linux/io_uring_types.h | io_arm_poll_handler | 1
| | /linux/io_uring_types.h | io_poll_add | 1
| | /linux/io_uring_types.h | io_poll_add_prep | 1
| | /linux/io_uring_types.h | io_poll_cancel | 1
| | /linux/io_uring_types.h | io_poll_remove | 1
| | /linux/io_uring_types.h | io_poll_remove_all | 1
| | /linux/io_uring_types.h | io_poll_remove_prep | 1
| | /linux/io_uring_types.h | io_poll_task_func | 1
cancel.h | /linux/io_uring_types.h | io_async_cancel | 1
| | /linux/io_uring_types.h | io_async_cancel_prep | 1
| | /linux/io_uring_types.h | io_cancel_req_match | 1
| | /linux/io_uring_types.h | io_sync_cancel | 1
| | /linux/io_uring_types.h | io_try_cancel | 1
alloc_cache.c | /linux/slab.h | free | 1
| | /linux/slab.h | kmalloc | 1
| | /linux/slab.h | kvfree | 1
| | arch/x86/include/asm/string_64.h | memset | 1
openclose.h | /linux/io_uring_types.h | __io_close_fixed | 1
| | /linux/io_uring_types.h | io_close | 1
| | /linux/io_uring_types.h | io_close_prep | 1
| | /linux/io_uring_types.h | io_install_fixed_fd | 1
| | /linux/io_uring_types.h | io_install_fixed_fd_prep | 1
| | /linux/io_uring_types.h | io_open_cleanup | 1
| | /linux/io_uring_types.h | io_openat | 1
| | /linux/io_uring_types.h | io_openat2 | 1
| | /linux/io_uring_types.h | io_openat2_prep | 1
| | /linux/io_uring_types.h | io_openat_prep | 1
waitid.h | /kernel/exit.h | io_waitid | 1
| | /kernel/exit.h | io_waitid_cancel | 1
| | /kernel/exit.h | io_waitid_prep | 1
| | /kernel/exit.h | io_waitid_remove_all | 1
truncate.h | /linux/io_uring_types.h | io_ftruncate | 1
| | /linux/io_uring_types.h | io_ftruncate_prep | 1
nop.h | /linux/io_uring_types.h | io_nop | 1
| | /linux/io_uring_types.h | io_nop_prep | 1
fdinfo.h | /linux/io_uring_types.h | io_uring_show_fdinfo | 1

Continue with the list untill all functions used in each source are listed.

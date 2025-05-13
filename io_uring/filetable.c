// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"

static int io_file_bitmap_get(struct io_ring_ctx *ctx)
{
	struct io_file_table *table = &ctx->file_table;
	unsigned long nr = ctx->file_alloc_end;
	int ret;

	if (!table->bitmap)
		return -ENFILE;

	do {
		ret = find_next_zero_bit(table->bitmap, nr, table->alloc_hint);
		if (ret != nr)
			return ret;

		if (table->alloc_hint == ctx->file_alloc_start)
			break;
		nr = table->alloc_hint;
		table->alloc_hint = ctx->file_alloc_start;
	} while (1);

	return -ENFILE;
}

/*
 * Function: io_alloc_file_tables
 * Description: Allocates memory for file tables in the io_ring context, including the bitmap for tracking allocated file slots.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 *   - table: Pointer to the io_file_table structure that will hold the allocated file tables.
 *   - nr_files: The number of files to be allocated for the table.
 * Returns:
 *   - true if successful, false if allocation fails.
 * Example usage:
 *   - This function is used to allocate memory for the file table and its bitmap in the IO ring context.
 */
bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table,
			  unsigned nr_files)
{
	if (io_rsrc_data_alloc(&table->data, nr_files))
		return false;
	table->bitmap = bitmap_zalloc(nr_files, GFP_KERNEL_ACCOUNT);
	if (table->bitmap)
		return true;
	io_rsrc_data_free(ctx, &table->data);
	return false;
}

/*
 * Function: io_free_file_tables
 * Description: Frees the resources associated with file tables, including the bitmap and allocated data.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 *   - table: Pointer to the io_file_table structure to be freed.
 * Returns:
 *   - void: This function does not return any value.
 * Example usage:
 *   - This function is used to release the memory allocated for the file table in the IO ring context.
 */
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table)
{
	io_rsrc_data_free(ctx, &table->data);
	bitmap_free(table->bitmap);
	table->bitmap = NULL;
}

static int io_install_fixed_file(struct io_ring_ctx *ctx, struct file *file,
				 u32 slot_index)
{
/*
 * Function: io_install_fixed_file
 * Description: Installs a fixed file into the IO ring context's file table at the specified slot.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 *   - file: Pointer to the file to be installed in the fixed file slot.
 *   - slot_index: The index in the file table where the file will be installed.
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function is called when installing a file into a specific slot in the file table of the IO ring context.
 */
__must_hold(&req->ctx->uring_lock)
{
	struct io_rsrc_node *node;

	if (io_is_uring_fops(file))
		return -EBADF;
	if (!ctx->file_table.data.nr)
		return -ENXIO;
	if (slot_index >= ctx->file_table.data.nr)
		return -EINVAL;

	node = io_rsrc_node_alloc(ctx, IORING_RSRC_FILE);
	if (!node)
		return -ENOMEM;

	if (!io_reset_rsrc_node(ctx, &ctx->file_table.data, slot_index))
		io_file_bitmap_set(&ctx->file_table, slot_index);

	ctx->file_table.data.nodes[slot_index] = node;
	io_fixed_file_set(node, file);
	return 0;
}

/*
 * Function: __io_fixed_fd_install
 * Description: Installs a fixed file descriptor into the IO ring context, allocating a slot if needed.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 *   - file: Pointer to the file to be installed.
 *   - file_slot: The index of the slot where the file will be installed, or a special value to allocate a new slot.
 * Returns:
 *   - The file slot index if successful, negative error code otherwise.
 * Example usage:
 *   - This function is used to install a file descriptor either at a specific slot or by allocating a new one in the IO ring context.
 */
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
			  unsigned int file_slot)
{
	bool alloc_slot = file_slot == IORING_FILE_INDEX_ALLOC;
	int ret;

	if (alloc_slot) {
		ret = io_file_bitmap_get(ctx);
		if (unlikely(ret < 0))
			return ret;
		file_slot = ret;
	} else {
		file_slot--;
	}

	ret = io_install_fixed_file(ctx, file, file_slot);
	if (!ret && alloc_slot)
		ret = file_slot;
	return ret;
}

/*
 * Function: io_fixed_fd_install
 * Description: Installs a fixed file descriptor into the IO ring context after ensuring proper locking and synchronization.
 * Parameters:
 *   - req: Pointer to the io_kiocb structure representing the IO request.
 *   - issue_flags: Flags indicating the type of operation (e.g., non-blocking).
 *   - file: Pointer to the file to be installed.
 *   - file_slot: The index of the slot where the file will be installed.
 * Returns:
 *   - The file slot index if successful, negative error code otherwise.
 * Example usage:
 *   - This function is used to install a fixed file descriptor, with proper locking, into the IO ring context.
 */
int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	io_ring_submit_lock(ctx, issue_flags);
	ret = __io_fixed_fd_install(ctx, file, file_slot);
	io_ring_submit_unlock(ctx, issue_flags);

	if (unlikely(ret < 0))
		fput(file);
	return ret;
}

/*
 * Function: io_fixed_fd_remove
 * Description: Removes a fixed file descriptor from the IO ring context's file table at the specified offset.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 *   - offset: The index of the file slot to be removed.
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function is used to remove a fixed file descriptor from the file table in the IO ring context.
 */
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset)
{
	struct io_rsrc_node *node;

	if (unlikely(!ctx->file_table.data.nr))
		return -ENXIO;
	if (offset >= ctx->file_table.data.nr)
		return -EINVAL;

	node = io_rsrc_node_lookup(&ctx->file_table.data, offset);
	if (!node)
		return -EBADF;
	io_reset_rsrc_node(ctx, &ctx->file_table.data, offset);
	io_file_bitmap_clear(&ctx->file_table, offset);
	return 0;
}

/*
 * Function: io_register_file_alloc_range
 * Description: Registers a range of file slots to be allocated within the IO ring context.
 * Parameters:
 *   - ctx: Pointer to the io_ring_ctx structure representing the IO ring context.
 *   - arg: A pointer to a user-space structure defining the range of file slots to allocate.
 * Returns:
 *   - 0 if successful, negative error code on failure.
 * Example usage:
 *   - This function is used to register a range of file slots for allocation in the IO ring context, based on user-space input.
 */
int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg)
{
	struct io_uring_file_index_range range;
	u32 end;

	if (copy_from_user(&range, arg, sizeof(range)))
		return -EFAULT;
	if (check_add_overflow(range.off, range.len, &end))
		return -EOVERFLOW;
	if (range.resv || end > ctx->file_table.data.nr)
		return -EINVAL;

	io_file_table_set_alloc_range(ctx, range.off, range.len);
	return 0;
}



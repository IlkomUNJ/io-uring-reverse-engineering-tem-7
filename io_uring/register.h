// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_REGISTER_H
#define IORING_REGISTER_H

/**
 * unregister all eventfd file descriptors from the given context
 */
int io_eventfd_unregister(struct io_ring_ctx *ctx);

/**
 * unregister a personality ID from the given context
 */
int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id);

/**
 * get a file pointer from a file descriptor, optionally from registered files
 */
struct file *io_uring_register_get_file(unsigned int fd, bool registered);

#endif

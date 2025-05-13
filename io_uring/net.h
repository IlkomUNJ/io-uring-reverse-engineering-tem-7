// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>
#include <linux/io_uring_types.h>

struct io_async_msghdr {
#if defined(CONFIG_NET)
	struct iou_vec				vec;

	struct_group(clear,
		int				namelen;
		struct iovec			fast_iov;
		__kernel_size_t			controllen;
		__kernel_size_t			payloadlen;
		struct sockaddr __user		*uaddr;
		struct msghdr			msg;
		struct sockaddr_storage		addr;
	);
#else
	struct_group(clear);
#endif
};

#if defined(CONFIG_NET)

/**
 * prepare and validate shutdown parameters before executing shutdown request
 */
int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * execute shutdown on a socket, disabling further send/receive operations
 */
int io_shutdown(struct io_kiocb *req, unsigned int issue_flags);

/**
 * cleanup resources allocated for sendmsg/recvmsg asynchronous operations
 */
void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req);
/**
 * prepare sendmsg request by validating parameters and setting up message headers
 */
int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * submit a sendmsg operation using previously prepared parameters
 */
int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags);

/**
 * submit a basic send operation for socket I/O
 */
int io_send(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare recvmsg request by validating input and setting up buffer structures
 */
int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * perform recvmsg operation, receiving message from a socket
 */
int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags);
/**
 * perform a basic receive operation on a socket
 */
int io_recv(struct io_kiocb *req, unsigned int issue_flags);

/**
 * handle error cleanup for failed send/receive requests
 */
void io_sendrecv_fail(struct io_kiocb *req);

/**
 * prepare accept request by checking parameters and initializing structures
 */
int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * perform accept operation to accept a new connection on a listening socket
 */
int io_accept(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare socket creation request based on parameters from user
 */
int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * create a new socket based on the prepared request
 */
int io_socket(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare connect request by validating socket and address
 */
int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * attempt to connect a socket to a remote address
 */
int io_connect(struct io_kiocb *req, unsigned int issue_flags);

/**
 * perform zero-copy send operation to reduce data copy overhead
 */
int io_send_zc(struct io_kiocb *req, unsigned int issue_flags);
/**
 * perform zero-copy variant of sendmsg operation
 */
int io_sendmsg_zc(struct io_kiocb *req, unsigned int issue_flags);
/**
 * prepare for zero-copy send operation by setting appropriate flags and buffers
 */
int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * release resources used by zero-copy send operations
 */
void io_send_zc_cleanup(struct io_kiocb *req);

/**
 * prepare bind operation by validating input socket and address
 */
int io_bind_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * bind a socket to a local address 
 */
int io_bind(struct io_kiocb *req, unsigned int issue_flags);

/**
 * prepare listen request for setting up a passive socket
 */
int io_listen_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * put a socket into listening state for accepting connections
 */
int io_listen(struct io_kiocb *req, unsigned int issue_flags);

/**
 * release memory used by cached network message structures
 */
void io_netmsg_cache_free(const void *entry);
#else
static inline void io_netmsg_cache_free(const void *entry)
{
}
#endif

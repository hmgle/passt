// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp_splice.c - direct namespace forwarding for local connections
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 *
 * For local traffic directed to TCP ports configured for direct mapping between
 * namespaces, packets are directly translated between L4 sockets using a pair
 * of splice() syscalls. These connections are tracked in the @tc array of
 * struct tcp_splice_conn, using these events:
 *
 * - SPLICE_CONNECT:		connection accepted, connecting to target
 * - SPLICE_ESTABLISHED:	connection to target established
 * - SPLICE_A_OUT_WAIT:		pipe to accepted socket full, wait for EPOLLOUT
 * - SPLICE_B_OUT_WAIT:		pipe to target socket full, wait for EPOLLOUT
 * - SPLICE_A_FIN_RCVD:		FIN (EPOLLRDHUP) seen from accepted socket
 * - SPLICE_B_FIN_RCVD:		FIN (EPOLLRDHUP) seen from target socket
 * - SPLICE_A_FIN_RCVD:		FIN (write shutdown) sent to accepted socket
 * - SPLICE_B_FIN_RCVD:		FIN (write shutdown) sent to target socket
 *
 * #syscalls:pasta pipe2|pipe fcntl armv6l:fcntl64 armv7l:fcntl64 ppc64:fcntl64
 */

#include <sched.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"
#include "passt.h"

#define MAX_PIPE_SIZE			(2UL * 1024 * 1024)
#define TCP_SPLICE_MAX_CONNS		(128 * 1024)
#define TCP_SPLICE_PIPE_POOL_SIZE	16
#define REFILL_INTERVAL			1000	/* ms, refill pool of pipes */

/* From tcp.c */
extern int init_sock_pool4		[TCP_SOCK_POOL_SIZE];
extern int init_sock_pool6		[TCP_SOCK_POOL_SIZE];
extern int ns_sock_pool4		[TCP_SOCK_POOL_SIZE];
extern int ns_sock_pool6		[TCP_SOCK_POOL_SIZE];

/* Pool of pre-opened pipes */
static int splice_pipe_pool		[TCP_SPLICE_PIPE_POOL_SIZE][2][2];

/**
 * struct tcp_splice_conn - Descriptor for a spliced TCP connection
 * @a:			File descriptor number of socket for accepted connection
 * @pipe_a_b:		Pipe ends for splice() from @a to @b
 * @b:			File descriptor number of peer connected socket
 * @pipe_b_a:		Pipe ends for splice() from @b to @a
 * @events:		Events observed/actions performed on connection
 * @flags:		Connection flags (attributes, not events)
 * @a_read:		Bytes read from @a (not fully written to @b in one shot)
 * @a_written:		Bytes written to @a (not fully written from one @b read)
 * @b_read:		Bytes read from @b (not fully written to @a in one shot)
 * @b_written:		Bytes written to @b (not fully written from one @a read)
*/
struct tcp_splice_conn {
	int a;
	int pipe_a_b[2];
	int b;
	int pipe_b_a[2];

	uint8_t events;
#define SPLICE_CLOSED			0
#define SPLICE_CONNECT			BIT(0)
#define SPLICE_ESTABLISHED		BIT(1)
#define SPLICE_A_OUT_WAIT		BIT(2)
#define SPLICE_B_OUT_WAIT		BIT(3)
#define SPLICE_A_FIN_RCVD		BIT(4)
#define SPLICE_B_FIN_RCVD		BIT(5)
#define SPLICE_A_FIN_SENT		BIT(6)
#define SPLICE_B_FIN_SENT		BIT(7)

	uint8_t flags;
#define SPLICE_V6			BIT(0)
#define SPLICE_IN_EPOLL			BIT(1)
#define SPLICE_RCVLOWAT_SET_A		BIT(2)
#define SPLICE_RCVLOWAT_SET_B		BIT(3)
#define SPLICE_RCVLOWAT_ACT_A		BIT(4)
#define SPLICE_RCVLOWAT_ACT_B		BIT(5)
#define SPLICE_CLOSING			BIT(6)

	uint64_t a_read;
	uint64_t a_written;
	uint64_t b_read;
	uint64_t b_written;
};

#define CONN_V6(x)			(x->flags & SPLICE_V6)
#define CONN_V4(x)			(!CONN_V6(x))
#define CONN_HAS(conn, set)		((conn->events & (set)) == (set))
#define CONN(index)			(tc + (index))

/* Spliced connections */
static struct tcp_splice_conn tc[TCP_SPLICE_MAX_CONNS];

/* Display strings for connection events */
static const char *tcp_splice_event_str[] __attribute((__unused__)) = {
	"SPLICE_CONNECT", "SPLICE_ESTABLISHED",
	"SPLICE_A_OUT_WAIT", "SPLICE_B_OUT_WAIT",
	"SPLICE_A_FIN_RCVD", "SPLICE_B_FIN_RCVD",
	"SPLICE_A_FIN_SENT", "SPLICE_B_FIN_SENT",
};

/* Display strings for connection flags */
static const char *tcp_splice_flag_str[] __attribute((__unused__)) = {
	"V6", "IN_EPOLL", "RCVLOWAT_SET_A", "RCVLOWAT_SET_B",
	"RCVLOWAT_ACT_A", "RCVLOWAT_ACT_B", "CLOSING",
};

/**
 * tcp_splice_conn_epoll_events() - epoll events masks for given state
 * @events:	Connection event flags
 * @a:		Event mask for socket with accepted connection, set on return
 * @b:		Event mask for connection target socket, set on return
 */
static void tcp_splice_conn_epoll_events(uint16_t events,
					 uint32_t *a, uint32_t *b)
{
	*a = *b = 0;

	if (events & SPLICE_CLOSED)
		return;

	if (events & SPLICE_ESTABLISHED)
		*a = *b = EPOLLIN | EPOLLRDHUP;
	else if (events & SPLICE_CONNECT)
		*b = EPOLLOUT;

	*a |= (events & SPLICE_A_OUT_WAIT) ? EPOLLOUT : 0;
	*b |= (events & SPLICE_B_OUT_WAIT) ? EPOLLOUT : 0;
}

static int tcp_splice_epoll_ctl(struct ctx *c, struct tcp_splice_conn *conn);

/**
 * conn_flag_do() - Set/unset given flag, log, update epoll on SPLICE_CLOSING
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flag:	Flag to set, or ~flag to unset
 */
static void conn_flag_do(struct ctx *c, struct tcp_splice_conn *conn,
			 unsigned long flag)
{
	if (flag & (flag - 1)) {
		if (!(conn->flags & ~flag))
			return;

		conn->flags &= flag;
		debug("TCP (spliced): index %i: %s dropped", (conn) - tc,
		      tcp_splice_flag_str[fls(~flag)]);
	} else {
		if (conn->flags & flag)
			return;

		conn->flags |= flag;
		debug("TCP (spliced): index %i: %s", (conn) - tc,
		      tcp_splice_flag_str[fls(flag)]);
	}

	if (flag == SPLICE_CLOSING)
		tcp_splice_epoll_ctl(c, conn);
}

#define conn_flag(c, conn, flag)					\
	do {								\
		trace("TCP (spliced): flag at %s:%i",			\
		      __func__, __LINE__);				\
		conn_flag_do(c, conn, flag);				\
	} while (0)

/**
 * tcp_splice_epoll_ctl() - Add/modify/delete epoll state from connection events
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, negative error code on failure (not on deletion)
 */
static int tcp_splice_epoll_ctl(struct ctx *c, struct tcp_splice_conn *conn)
{
	int m = (conn->flags & SPLICE_IN_EPOLL) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	union epoll_ref ref_a = { .r.proto = IPPROTO_TCP, .r.s = conn->a,
				  .r.p.tcp.tcp.splice = 1,
				  .r.p.tcp.tcp.index = conn - tc,
				  .r.p.tcp.tcp.v6 = CONN_V6(conn) };
	union epoll_ref ref_b = { .r.proto = IPPROTO_TCP, .r.s = conn->b,
				  .r.p.tcp.tcp.splice = 1,
				  .r.p.tcp.tcp.index = conn - tc,
				  .r.p.tcp.tcp.v6 = CONN_V6(conn) };
	struct epoll_event ev_a = { .data.u64 = ref_a.u64 };
	struct epoll_event ev_b = { .data.u64 = ref_b.u64 };
	uint32_t events_a, events_b;

	if (conn->flags & SPLICE_CLOSING) {
		if (conn->flags & SPLICE_IN_EPOLL)
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->a, &ev_a);

		if (conn->events & SPLICE_CONNECT)
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->b, &ev_b);

		return 0;
	}

	tcp_splice_conn_epoll_events(conn->events, &events_a, &events_b);
	ev_a.events = events_a;
	ev_b.events = events_b;

	if (epoll_ctl(c->epollfd, m, conn->a, &ev_a) ||
	    epoll_ctl(c->epollfd, m, conn->b, &ev_b))
		goto err;

	conn->flags |= SPLICE_IN_EPOLL;		/* No need to log this */

	return 0;

err:
	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->a, &ev_a);
	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->b, &ev_b);
	return -errno;
}

/**
 * conn_event_do() - Set and log connection events, update epoll state
 * @c:		Execution context
 * @conn:	Connection pointer
 * @event:	Connection event
 */
static void conn_event_do(struct ctx *c, struct tcp_splice_conn *conn,
			  unsigned long event)
{
	if (event == SPLICE_CLOSED) {
		conn->events = SPLICE_CLOSED;
		debug("TCP (spliced): index %i, CLOSED", conn - tc);
		return;
	}

	if (event & (event - 1)) {
		if (!(conn->events & ~event))
			return;

		conn->events &= event;
		debug("TCP (spliced): index %i, ~%s", conn - tc,
		      tcp_splice_event_str[fls(~event)]);
	} else {
		if (conn->events & event)
			return;

		conn->events |= event;
		debug("TCP (spliced): index %i, %s", conn - tc,
		      tcp_splice_event_str[fls(event)]);
	}

	if (tcp_splice_epoll_ctl(c, conn))
		conn_flag(c, conn, SPLICE_CLOSING);
}

#define conn_event(c, conn, event)					\
	do {								\
		trace("TCP (spliced): event at %s:%i",			\
		      __func__, __LINE__);				\
		conn_event_do(c, conn, event);				\
	} while (0)

/**
 * tcp_table_splice_compact - Compact spliced connection table
 * @c:		Execution context
 * @hole:	Pointer to recently closed connection
 */
static void tcp_table_splice_compact(struct ctx *c,
				     struct tcp_splice_conn *hole)
{
	struct tcp_splice_conn *move;

	if ((hole - tc) == --c->tcp.splice_conn_count) {
		debug("TCP (spliced): index %i (max) removed", hole - tc);
		return;
	}

	move = CONN(c->tcp.splice_conn_count);

	memcpy(hole, move, sizeof(*hole));

	move->a = move->b = -1;
	move->flags = move->events = 0;
	move->a_read = move->a_written = move->b_read = move->b_written = 0;

	debug("TCP (spliced): index %i moved to %i", move - tc, hole - tc);
	if (tcp_splice_epoll_ctl(c, hole))
		conn_flag(c, hole, SPLICE_CLOSING);
}

/**
 * tcp_splice_destroy() - Close spliced connection and pipes, drop from epoll
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_splice_destroy(struct ctx *c, struct tcp_splice_conn *conn)
{
	if (conn->events & SPLICE_ESTABLISHED) {
		/* Flushing might need to block: don't recycle them. */
		if (conn->pipe_a_b[0] != -1) {
			close(conn->pipe_a_b[0]);
			close(conn->pipe_a_b[1]);
			conn->pipe_a_b[0] = conn->pipe_a_b[1] = -1;
		}
		if (conn->pipe_b_a[0] != -1) {
			close(conn->pipe_b_a[0]);
			close(conn->pipe_b_a[1]);
			conn->pipe_b_a[0] = conn->pipe_b_a[1] = -1;
		}
	}

	if (conn->events & SPLICE_CONNECT) {
		close(conn->b);
		conn->b = -1;
	}

	conn_event(c, conn, SPLICE_CLOSED);

	close(conn->a);
	conn->a = -1;
	conn->flags = 0;
	conn->a_read = conn->a_written = conn->b_read = conn->b_written = 0;

	tcp_table_splice_compact(c, conn);
}

/**
 * tcp_splice_connect_finish() - Completion of connect() or call on success
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, -EIO on failure
 */
static int tcp_splice_connect_finish(struct ctx *c,
				     struct tcp_splice_conn *conn)
{
	int i;

	conn->pipe_a_b[0] = conn->pipe_b_a[0] = -1;
	conn->pipe_a_b[1] = conn->pipe_b_a[1] = -1;

	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
		if (splice_pipe_pool[i][0][0] > 0) {
			SWAP(conn->pipe_a_b[0], splice_pipe_pool[i][0][0]);
			SWAP(conn->pipe_a_b[1], splice_pipe_pool[i][0][1]);

			SWAP(conn->pipe_b_a[0], splice_pipe_pool[i][1][0]);
			SWAP(conn->pipe_b_a[1], splice_pipe_pool[i][1][1]);
			break;
		}
	}

	if (conn->pipe_a_b[0] < 0) {
		if (pipe2(conn->pipe_a_b, O_NONBLOCK) ||
		    pipe2(conn->pipe_b_a, O_NONBLOCK)) {
			conn_flag(c, conn, SPLICE_CLOSING);
			return -EIO;
		}

		fcntl(conn->pipe_a_b[0], F_SETPIPE_SZ, c->tcp.pipe_size);
		fcntl(conn->pipe_b_a[0], F_SETPIPE_SZ, c->tcp.pipe_size);
	}

	if (!(conn->events & SPLICE_ESTABLISHED))
		conn_event(c, conn, SPLICE_ESTABLISHED);

	return 0;
}

/**
 * tcp_splice_connect() - Create and connect socket for new spliced connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @s:		Accepted socket
 * @port:	Destination port, host order
 *
 * Return: 0 for connect() succeeded or in progress, negative value on error
 */
static int tcp_splice_connect(struct ctx *c, struct tcp_splice_conn *conn,
			      int s, in_port_t port)
{
	int sock_conn = (s >= 0) ? s : socket(CONN_V6(conn) ? AF_INET6 :
							      AF_INET,
					      SOCK_STREAM | SOCK_NONBLOCK,
					      IPPROTO_TCP);
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
	};
	const struct sockaddr *sa;
	socklen_t sl;

	if (sock_conn < 0)
		return -errno;

	if (sock_conn > SOCKET_MAX) {
		close(sock_conn);
		return -EIO;
	}

	conn->b = sock_conn;

	if (s < 0)
		tcp_sock_set_bufsize(c, conn->b);

	setsockopt(conn->b, SOL_TCP, TCP_QUICKACK, &((int){ 1 }), sizeof(int));

	if (CONN_V6(conn)) {
		sa = (struct sockaddr *)&addr6;
		sl = sizeof(addr6);
	} else {
		sa = (struct sockaddr *)&addr4;
		sl = sizeof(addr4);
	}

	if (connect(conn->b, sa, sl)) {
		if (errno != EINPROGRESS) {
			int ret = -errno;

			close(sock_conn);
			return ret;
		}
		conn_event(c, conn, SPLICE_CONNECT);
	} else {
		conn_event(c, conn, SPLICE_ESTABLISHED);
		return tcp_splice_connect_finish(c, conn);
	}

	return 0;
}

/**
 * struct tcp_splice_connect_ns_arg - Arguments for tcp_splice_connect_ns()
 * @c:		Execution context
 * @conn:	Accepted inbound connection
 * @port:	Destination port, host order
 * @ret:	Return value of tcp_splice_connect_ns()
 */
struct tcp_splice_connect_ns_arg {
	struct ctx *c;
	struct tcp_splice_conn *conn;
	in_port_t port;
	int ret;
};

/**
 * tcp_splice_connect_ns() - Enter namespace and call tcp_splice_connect()
 * @arg:	See struct tcp_splice_connect_ns_arg
 *
 * Return: 0
 */
static int tcp_splice_connect_ns(void *arg)
{
	struct tcp_splice_connect_ns_arg *a;

	a = (struct tcp_splice_connect_ns_arg *)arg;
	ns_enter(a->c);
	a->ret = tcp_splice_connect(a->c, a->conn, -1, a->port);
	return 0;
}

/**
 * tcp_splice_new() - Handle new inbound, spliced connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @port:	Destination port, host order
 *
 * Return: return code from connect()
 */
static int tcp_splice_new(struct ctx *c, struct tcp_splice_conn *conn,
			  in_port_t port)
{
	struct tcp_splice_connect_ns_arg ns_arg = { c, conn, port, 0 };
	int *sock_pool_p, i, s = -1;

	if (bitmap_isset(c->tcp.port_to_tap, port))
		sock_pool_p = CONN_V6(conn) ? ns_sock_pool6 : ns_sock_pool4;
	else
		sock_pool_p = CONN_V6(conn) ? init_sock_pool6 : init_sock_pool4;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++, sock_pool_p++) {
		if ((s = *sock_pool_p) >= 0) {
			*sock_pool_p = -1;
			break;
		}
	}

	if (s < 0 && bitmap_isset(c->tcp.port_to_tap, port)) {
		NS_CALL(tcp_splice_connect_ns, &ns_arg);
		return ns_arg.ret;
	}

	return tcp_splice_connect(c, conn, s, port);
}

/**
 * tcp_splice_dir() - Set sockets/pipe pointers reflecting flow direction
 * @conn:	Connection pointers
 * @ref_sock:	Socket returned as reference from epoll
 * @reverse:	Reverse direction: @ref_sock is used as destination
 * @from:	Destination socket pointer to set
 * @to:		Source socket pointer to set
 * @pipes:	Pipe set, assigned on return
 */
static void tcp_splice_dir(struct tcp_splice_conn *conn, int ref_sock,
			   int reverse, int *from, int *to, int **pipes)
{
	if (!reverse) {
		*from = ref_sock;
		*to   = (*from == conn->a) ? conn->b : conn->a;
	} else {
		*to   = ref_sock;
		*from = (*to   == conn->a) ? conn->b : conn->a;
	}

	*pipes = *from == conn->a ? conn->pipe_a_b : conn->pipe_b_a;
}

/**
 * tcp_sock_handler_splice() - Handler for socket mapped to spliced connection
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 *
 * #syscalls:pasta splice
 */
void tcp_sock_handler_splice(struct ctx *c, union epoll_ref ref,
			     uint32_t events)
{
	uint8_t lowat_set_flag, lowat_act_flag;
	int from, to, *pipes, eof, never_read;
	uint64_t *seq_read, *seq_write;
	struct tcp_splice_conn *conn;

	if (ref.r.p.tcp.tcp.listen) {
		int s;

		if (c->tcp.splice_conn_count >= TCP_SPLICE_MAX_CONNS)
			return;

		if ((s = accept4(ref.r.s, NULL, NULL, SOCK_NONBLOCK)) < 0)
			return;

		setsockopt(s, SOL_TCP, TCP_QUICKACK, &((int){ 1 }),
			   sizeof(int));

		conn = CONN(c->tcp.splice_conn_count++);
		conn->a = s;
		conn->flags = ref.r.p.tcp.tcp.v6 ? SPLICE_V6 : 0;

		if (tcp_splice_new(c, conn, ref.r.p.tcp.tcp.index))
			conn_flag(c, conn, SPLICE_CLOSING);

		return;
	}

	conn = CONN(ref.r.p.tcp.tcp.index);

	if (events & EPOLLERR || events & EPOLLHUP)
		goto close;

	if (conn->events == SPLICE_CONNECT) {
		if (!(events & EPOLLOUT))
			goto close;
		if (tcp_splice_connect_finish(c, conn))
			goto close;
	}

	if (events & EPOLLOUT) {
		if (ref.r.s == conn->a)
			conn_event(c, conn, ~SPLICE_A_OUT_WAIT);
		else
			conn_event(c, conn, ~SPLICE_B_OUT_WAIT);

		tcp_splice_dir(conn, ref.r.s, 1, &from, &to, &pipes);
	} else {
		tcp_splice_dir(conn, ref.r.s, 0, &from, &to, &pipes);
	}

	if (events & EPOLLRDHUP) {
		if (ref.r.s == conn->a)
			conn_event(c, conn, SPLICE_A_FIN_RCVD);
		else
			conn_event(c, conn, SPLICE_B_FIN_RCVD);
	}

swap:
	eof = 0;
	never_read = 1;

	if (from == conn->a) {
		seq_read = &conn->a_read;
		seq_write = &conn->a_written;
		lowat_set_flag = SPLICE_RCVLOWAT_SET_A;
		lowat_act_flag = SPLICE_RCVLOWAT_ACT_A;
	} else {
		seq_read = &conn->b_read;
		seq_write = &conn->b_written;
		lowat_set_flag = SPLICE_RCVLOWAT_SET_B;
		lowat_act_flag = SPLICE_RCVLOWAT_ACT_B;
	}

	while (1) {
		int retry_write = 0, more = 0;
		ssize_t readlen, to_write = 0, written;

retry:
		readlen = splice(from, NULL, pipes[1], NULL, c->tcp.pipe_size,
				 SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (readlen < 0) {
			if (errno == EINTR)
				goto retry;

			if (errno != EAGAIN)
				goto close;

			to_write = c->tcp.pipe_size;
		} else if (!readlen) {
			eof = 1;
			to_write = c->tcp.pipe_size;
		} else {
			never_read = 0;
			to_write += readlen;
			if (readlen >= (long)c->tcp.pipe_size * 90 / 100)
				more = SPLICE_F_MORE;

			if (conn->flags & lowat_set_flag)
				conn_flag(c, conn, lowat_act_flag);
		}

eintr:
		written = splice(pipes[0], NULL, to, NULL, to_write,
				 SPLICE_F_MOVE | more | SPLICE_F_NONBLOCK);

		/* Most common case: skip updating counters. */
		if (readlen > 0 && readlen == written) {
			if (readlen >= (long)c->tcp.pipe_size * 10 / 100)
				continue;

			if (conn->flags & lowat_set_flag &&
			    readlen > (long)c->tcp.pipe_size / 10) {
				int lowat = c->tcp.pipe_size / 4;

				setsockopt(from, SOL_SOCKET, SO_RCVLOWAT,
					   &lowat, sizeof(lowat));

				conn_flag(c, conn, lowat_set_flag);
				conn_flag(c, conn, lowat_act_flag);
			}

			break;
		}

		*seq_read  += readlen > 0 ? readlen : 0;
		*seq_write += written > 0 ? written : 0;

		if (written < 0) {
			if (errno == EINTR)
				goto eintr;

			if (errno != EAGAIN)
				goto close;

			if (never_read)
				break;

			if (retry_write--)
				goto retry;

			if (to == conn->a)
				conn_event(c, conn, SPLICE_A_OUT_WAIT);
			else
				conn_event(c, conn, SPLICE_B_OUT_WAIT);
			break;
		}

		if (never_read && written == (long)(c->tcp.pipe_size))
			goto retry;

		if (!never_read && written < to_write) {
			to_write -= written;
			goto retry;
		}

		if (eof)
			break;
	}

	if ( (conn->events & SPLICE_A_FIN_RCVD) &&
	    !(conn->events & SPLICE_B_FIN_SENT)) {
		if (*seq_read == *seq_write) {
			shutdown(conn->b, SHUT_WR);
			conn_event(c, conn, SPLICE_B_FIN_SENT);
		}
	}

	if ( (conn->events & SPLICE_B_FIN_RCVD) &&
	    !(conn->events & SPLICE_A_FIN_SENT)) {
		if (*seq_read == *seq_write) {
			shutdown(conn->a, SHUT_WR);
			conn_event(c, conn, SPLICE_A_FIN_SENT);
		}
	}

	if (CONN_HAS(conn, SPLICE_A_FIN_SENT | SPLICE_B_FIN_SENT))
		goto close;

	if ((events & (EPOLLIN | EPOLLOUT)) == (EPOLLIN | EPOLLOUT)) {
		events = EPOLLIN;

		SWAP(from, to);
		if (pipes == conn->pipe_a_b)
			pipes = conn->pipe_b_a;
		else
			pipes = conn->pipe_a_b;

		goto swap;
	}

	return;

close:
	conn_flag(c, conn, SPLICE_CLOSING);
}

/**
 * tcp_set_pipe_size() - Set usable pipe size, probe starting from MAX_PIPE_SIZE
 * @c:		Execution context
 */
static void tcp_set_pipe_size(struct ctx *c)
{
	int probe_pipe[TCP_SPLICE_PIPE_POOL_SIZE * 2][2], i, j;

	c->tcp.pipe_size = MAX_PIPE_SIZE;

smaller:
	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE * 2; i++) {
		if (pipe2(probe_pipe[i], 0)) {
			i++;
			break;
		}

		if (fcntl(probe_pipe[i][0], F_SETPIPE_SZ, c->tcp.pipe_size) < 0)
			break;
	}

	for (j = i - 1; j >= 0; j--) {
		close(probe_pipe[j][0]);
		close(probe_pipe[j][1]);
	}

	if (i == TCP_SPLICE_PIPE_POOL_SIZE * 2)
		return;

	if (!(c->tcp.pipe_size /= 2)) {
		c->tcp.pipe_size = MAX_PIPE_SIZE;
		return;
	}

	goto smaller;
}

/**
 * tcp_splice_pipe_refill() - Refill pool of pre-opened pipes
 * @c:		Execution context
 */
static void tcp_splice_pipe_refill(struct ctx *c)
{
	int i;

	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
		if (splice_pipe_pool[i][0][0] >= 0)
			break;
		if (pipe2(splice_pipe_pool[i][0], O_NONBLOCK))
			continue;
		if (pipe2(splice_pipe_pool[i][1], O_NONBLOCK)) {
			close(splice_pipe_pool[i][1][0]);
			close(splice_pipe_pool[i][1][1]);
			continue;
		}

		fcntl(splice_pipe_pool[i][0][0], F_SETPIPE_SZ,
		      c->tcp.pipe_size);
		fcntl(splice_pipe_pool[i][1][0], F_SETPIPE_SZ,
		      c->tcp.pipe_size);
	}
}

/**
 * tcp_splice_init() - Initialise pipe pool and size
 * @c:		Execution context
 */
void tcp_splice_init(struct ctx *c)
{
	memset(splice_pipe_pool, 0xff, sizeof(splice_pipe_pool));
	tcp_set_pipe_size(c);
	tcp_splice_pipe_refill(c);
}

/**
 * tcp_splice_timer() - Timer for spliced connections
 * @c:		Execution context
 * @now:	Current timestamp
 */
void tcp_splice_timer(struct ctx *c, struct timespec *now)
{
	int i;

	for (i = c->tcp.splice_conn_count - 1; i >= 0; i--) {
		struct tcp_splice_conn *conn;

		conn = CONN(i);

		if (conn->flags & SPLICE_CLOSING) {
			tcp_splice_destroy(c, conn);
			continue;
		}

		if ( (conn->flags & SPLICE_RCVLOWAT_SET_A) &&
		    !(conn->flags & SPLICE_RCVLOWAT_ACT_A)) {
			setsockopt(conn->a, SOL_SOCKET, SO_RCVLOWAT,
				   &((int){ 1 }), sizeof(int));
			conn_flag(c, conn, ~SPLICE_RCVLOWAT_SET_A);
		}

		if ( (conn->flags & SPLICE_RCVLOWAT_SET_B) &&
		    !(conn->flags & SPLICE_RCVLOWAT_ACT_B)) {
			setsockopt(conn->b, SOL_SOCKET, SO_RCVLOWAT,
				   &((int){ 1 }), sizeof(int));
			conn_flag(c, conn, ~SPLICE_RCVLOWAT_SET_B);
		}

		conn_flag(c, conn, ~SPLICE_RCVLOWAT_ACT_A);
		conn_flag(c, conn, ~SPLICE_RCVLOWAT_ACT_B);
	}

	if (timespec_diff_ms(now, &c->tcp.refill_ts) > REFILL_INTERVAL)
		tcp_splice_pipe_refill(c);
}

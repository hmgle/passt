// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * udp.c - UDP L2-L4 translation routines
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 *
 * For UDP, a reduced version of port-based connection tracking is implemented
 * with two purposes:
 * - binding ephemeral ports when they're used as source port by the guest, so
 *   that replies on those ports can be forwarded back to the guest, with a
 *   fixed timeout for this binding
 * - packets received from the local host get their source changed to a local
 *   address (gateway address) so that they can be forwarded to the guest, and
 *   packets sent as replies by the guest need their destination address to
 *   be changed back to the address of the local host. This is dynamic to allow
 *   connections from the gateway as well, and uses the same fixed 180s timeout
 * 
 * Sockets for bound ports are created at initialisation time, one set for IPv4
 * and one for IPv6.
 *
 * Packets are forwarded back and forth, by prepending and stripping UDP headers
 * in the obvious way, with no port translation.
 *
 * In PASTA mode, the L2-L4 translation is skipped for connections to ports
 * bound between namespaces using the loopback interface, messages are directly
 * transferred between L4 sockets instead. These are called spliced connections
 * for consistency with the TCP implementation, but the splice() syscall isn't
 * actually used as it wouldn't make sense for datagram-based connections: a
 * pair of recvmmsg() and sendmmsg() deals with this case.
 *
 * The connection tracking for PASTA mode is slightly complicated by the absence
 * of actual connections, see struct udp_splice_port, and these examples:
 *
 * - from init to namespace:
 *
 *   - forward direction: 127.0.0.1:5000 -> 127.0.0.1:80 in init from bound
 *     socket s, with epoll reference: index = 80, splice = UDP_TO_NS
 *     - if udp_splice_map[V4][5000].ns_conn_sock:
 *       - send packet to udp4_splice_map[5000].ns_conn_sock
 *     - otherwise:
 *       - create new socket udp_splice_map[V4][5000].ns_conn_sock
 *       - connect in namespace to 127.0.0.1:80
 *       - get source port of new connected socket (10000) with getsockname()
 *       - add to epoll with reference: index = 10000, splice: UDP_BACK_TO_INIT
 *       - set udp_splice_map[V4][10000].init_bound_sock to s
 *       - set udp_splice_map[V4][10000].init_dst_port to 5000
 *   - update udp_splice_map[V4][5000].ns_conn_ts with current time
 *
 *   - reverse direction: 127.0.0.1:80 -> 127.0.0.1:10000 in namespace from
 *     connected socket s, having epoll reference: index = 10000,
 *     splice = UDP_BACK_TO_INIT
 *     - if udp_splice_map[V4][10000].init_bound_sock:
 *       - send to udp_splice_map[V4][10000].init_bound_sock, with destination
 *         port udp_splice_map[V4][10000].init_dst_port (5000)
 *     - otherwise, discard
 *
 * - from namespace to init:
 *
 *   - forward direction: 127.0.0.1:2000 -> 127.0.0.1:22 in namespace from bound
 *     socket s, with epoll reference: index = 22, splice = UDP_TO_INIT
 *     - if udp4_splice_map[V4][2000].init_conn_sock:
 *       - send packet to udp4_splice_map[2000].init_conn_sock
 *     - otherwise:
 *       - create new socket udp_splice_map[V4][2000].init_conn_sock
 *       - connect in init to 127.0.0.1:22,
 *       - get source port of new connected socket (4000) with getsockname()
 *       - add to epoll with reference: index = 4000, splice = UDP_BACK_TO_NS
 *       - set udp_splice_map[V4][4000].ns_bound_sock to s
 *       - set udp_splice_map[V4][4000].ns_dst_port to 2000
 *     - update udp_splice_map[V4][4000].init_conn_ts with current time
 *
 *   - reverse direction: 127.0.0.1:22 -> 127.0.0.1:4000 in init from connected
 *     socket s, having epoll reference: index = 4000, splice = UDP_BACK_TO_NS
 *   - if udp_splice_map[V4][4000].ns_bound_sock:
 *     - send to udp_splice_map[V4][4000].ns_bound_sock, with destination port
 *       udp_splice_map[4000].ns_dst_port (2000)
 *   - otherwise, discard
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <time.h>

#include "util.h"
#include "passt.h"
#include "tap.h"

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */
#define UDP_SPLICE_FRAMES	128

/**
 * struct udp_tap_port - Port tracking based on tap-facing source port
 * @sock:	Socket bound to source port used as index
 * @ts:		Activity timestamp from tap, used for socket aging
 * @ts_local:	Timestamp of tap packet to gateway address, aging for local bind
 */
struct udp_tap_port {
	int sock;
	time_t ts;
	time_t ts_local;
};

/**
 * struct udp_splice_port - Source port tracking for traffic between namespaces
 * @ns_conn_sock:	Socket connected in namespace for init source port
 * @init_conn_sock:	Socket connected in init for namespace source port
 * @ns_conn_ts:		Timestamp of activity for socket connected in namespace
 * @init_conn_ts:	Timestamp of activity for socket connceted in init
 * @ns_dst_port:	Destination port in namespace for init source port
 * @init_dst_port:	Destination port in init for namespace source port
 * @ns_bound_sock:	Bound socket in namespace for this source port in init
 * @init_bound_sock:	Bound socket in init for this source port in namespace
 */
struct udp_splice_port {
	int ns_conn_sock;
	int init_conn_sock;

	time_t ns_conn_ts;
	time_t init_conn_ts;

	in_port_t ns_dst_port;
	in_port_t init_dst_port;

	int ns_bound_sock;
	int init_bound_sock;
};

/* Port tracking, arrays indexed by packet source port (host order) */
static struct udp_tap_port	udp_tap_map	[IP_VERSIONS][USHRT_MAX];
static struct udp_splice_port	udp_splice_map	[IP_VERSIONS][USHRT_MAX];

enum udp_act_type {
	UDP_ACT_TAP,
	UDP_ACT_NS_CONN,
	UDP_ACT_INIT_CONN,
	UDP_ACT_TYPE_MAX,
};

/* Activity-based aging for bindings */
static uint8_t udp_act[IP_VERSIONS][UDP_ACT_TYPE_MAX][USHRT_MAX / 8];

/* recvmmsg()/sendmmsg() data */
static struct sockaddr_storage udp_splice_namebuf;
static uint8_t udp_splice_buf[UDP_SPLICE_FRAMES][USHRT_MAX];

static struct iovec	udp_splice_iov_recv	[UDP_SPLICE_FRAMES];
static struct mmsghdr	udp_splice_mmh_recv	[UDP_SPLICE_FRAMES];

static struct iovec	udp_splice_iov_send	[UDP_SPLICE_FRAMES];
static struct mmsghdr	udp_splice_mmh_send	[UDP_SPLICE_FRAMES];

static struct iovec	udp_splice_iov_sendto	[UDP_SPLICE_FRAMES];
static struct mmsghdr	udp_splice_mmh_sendto	[UDP_SPLICE_FRAMES];

/**
 * udp_splice_connect() - Create and connect socket for "spliced" binding
 * @c:		Execution context
 * @v6:		Set for IPv6 connections
 * @bound_sock:	Originating bound socket
 * @src:	Source port of original connection, host order
 * @dst:	Destination port of original connection, host order
 * @splice:	UDP_BACK_TO_INIT from init, UDP_BACK_TO_NS from namespace
 *
 * Return: connected socket, negative error code on failure
 */
int udp_splice_connect(struct ctx *c, int v6, int bound_sock,
		       in_port_t src, in_port_t dst, int splice)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLHUP };
	union epoll_ref ref = { .proto = IPPROTO_UDP,
				 .udp = { .splice = splice, .v6 = v6 }
			      };
	struct sockaddr_storage sa;
	struct udp_splice_port *sp;
	socklen_t sl = sizeof(sa);
	int s;

	s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK,
		   IPPROTO_UDP);
	if (s < 0)
		return s;
	ref.s = s;

	if (v6) {
		struct sockaddr_in6 addr6 = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(dst),
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		};
		if (connect(s, (struct sockaddr *)&addr6, sizeof(addr6)))
			goto fail;
	} else {
		struct sockaddr_in addr4 = {
			.sin_family = AF_INET,
			.sin_port = htons(dst),
			.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		};
		if (connect(s, (struct sockaddr *)&addr4, sizeof(addr4)))
			goto fail;
	}

	if (getsockname(s, (struct sockaddr *)&sa, &sl))
		goto fail;

	if (v6)
		ref.udp.port = ntohs(((struct sockaddr_in6 *)&sa)->sin6_port);
	else
		ref.udp.port = ntohs(((struct sockaddr_in *)&sa)->sin_port);

	sp = &udp_splice_map[v6 ? V6 : V4][ref.udp.port];
	if (splice == UDP_BACK_TO_INIT) {
		sp->init_bound_sock = bound_sock;
		sp->init_dst_port = src;
		udp_splice_map[v6 ? V6 : V4][src].ns_conn_sock = s;
		bitmap_set(udp_act[v6 ? V6 : V4][UDP_ACT_NS_CONN], src);
	} else if (splice == UDP_BACK_TO_NS) {
		sp->ns_bound_sock = bound_sock;
		sp->ns_dst_port = src;
		udp_splice_map[v6 ? V6 : V4][src].init_conn_sock = s;
		bitmap_set(udp_act[v6 ? V6 : V4][UDP_ACT_INIT_CONN], src);
	}

	ev.data.u64 = ref.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, s, &ev);
	return s;

fail:
	close(s);
	return -1;
}

/**
 * struct udp_splice_connect_ns_arg - Arguments for udp_splice_connect_ns()
 * @c:		Execution context
 * @v6:		Set for inbound IPv6 connection
 * @bound_sock:	Originating bound socket
 * @src:	Source port of original connection, host order
 * @dst:	Destination port of original connection, host order
 * @s:		Newly created socket or negative error code
 */
struct udp_splice_connect_ns_arg {
	struct ctx *c;
	int v6;
	int bound_sock;
	in_port_t src;
	in_port_t dst;
	int s;
};

/**
 * udp_splice_connect_ns() - Enter namespace and call udp_splice_connect()
 * @arg:	See struct udp_splice_connect_ns_arg
 *
 * Return: 0
 */
static int udp_splice_connect_ns(void *arg)
{
	struct udp_splice_connect_ns_arg *a;

	a = (struct udp_splice_connect_ns_arg *)arg;

	ns_enter(a->c->pasta_pid);
	a->s = udp_splice_connect(a->c, a->v6, a->bound_sock, a->src, a->dst,
				  UDP_BACK_TO_INIT);

	return 0;
}

/**
 * udp_sock_handler_splice() - Handler for socket mapped to "spliced" connection
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
static void udp_sock_handler_splice(struct ctx *c, union epoll_ref ref,
				    uint32_t events, struct timespec *now)
{
	struct msghdr *mh = &udp_splice_mmh_recv[0].msg_hdr;
	struct sockaddr_storage *sa_s = mh->msg_name;
	in_port_t src, dst = ref.udp.port, send_dst;
	char ns_fn_stack[NS_FN_STACK_SIZE];
	int s, v6 = ref.udp.v6, n, i;

	if (!(events & EPOLLIN))
		return;

	n = recvmmsg(ref.s, udp_splice_mmh_recv, UDP_SPLICE_FRAMES, 0, NULL);

	if (n <= 0)
		return;

	if (v6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)sa_s;

		src = htons(sa->sin6_port);
	} else {
		struct sockaddr_in *sa = (struct sockaddr_in *)sa_s;

		src = ntohs(sa->sin_port);
	}

	switch (ref.udp.splice) {
	case UDP_TO_NS:
		if (!(s = udp_splice_map[v6][src].ns_conn_sock)) {
			struct udp_splice_connect_ns_arg arg = {
				c, v6, ref.s, src, dst, -1,
			};

			clone(udp_splice_connect_ns,
			      ns_fn_stack + sizeof(ns_fn_stack) / 2,
			      CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD,
			      (void *)&arg);

			if ((s = arg.s) < 0)
				return;
		}
		udp_splice_map[v6][src].ns_conn_ts = now->tv_sec;
		break;
	case UDP_BACK_TO_INIT:
		if (!(s = udp_splice_map[v6][dst].init_bound_sock))
			return;

		send_dst = udp_splice_map[v6][dst].init_dst_port;
		break;
	case UDP_TO_INIT:
		if (!(s = udp_splice_map[v6][src].init_conn_sock)) {
			s = udp_splice_connect(c, v6, ref.s, src, dst,
					       UDP_BACK_TO_NS);
			if (s < 0)
				return;
		}
		udp_splice_map[v6][src].init_conn_ts = now->tv_sec;
		break;
	case UDP_BACK_TO_NS:
		if (!(s = udp_splice_map[v6][dst].ns_bound_sock))
			return;

		send_dst = udp_splice_map[v6][dst].ns_dst_port;
		break;
	default:
		return;
	}

	if (ref.udp.splice == UDP_TO_NS || ref.udp.splice == UDP_TO_INIT) {
		for (i = 0; i < n; i++) {
			struct msghdr *mh = &udp_splice_mmh_send[i].msg_hdr;

			mh->msg_iov->iov_len = udp_splice_mmh_recv[i].msg_len;
		}

		sendmmsg(s, udp_splice_mmh_send, n, MSG_NOSIGNAL);
		return;
	}

	for (i = 0; i < n; i++) {
		struct msghdr *mh = &udp_splice_mmh_sendto[i].msg_hdr;

		mh->msg_iov->iov_len = udp_splice_mmh_recv[i].msg_len;
	}

	if (v6) {
		*((struct sockaddr_in6 *)&udp_splice_namebuf) =
		 ((struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
			.sin6_port = htons(send_dst),
		});
	} else {
		*((struct sockaddr_in *)&udp_splice_namebuf) =
		 ((struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
			.sin_port = htons(send_dst),
		});
	}

	sendmmsg(s, udp_splice_mmh_sendto, n, MSG_NOSIGNAL);
}

/**
 * udp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
void udp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      struct timespec *now)
{
	struct sockaddr_storage sr;
	socklen_t sl = sizeof(sr);
	char buf[USHRT_MAX];
	struct udphdr *uh;
	ssize_t n;

	if (events == EPOLLERR)
		return;

	if (ref.udp.splice) {
		udp_sock_handler_splice(c, ref, events, now);
		return;
	}

	uh = (struct udphdr *)buf;

	n = recvfrom(ref.s, buf + sizeof(*uh), sizeof(buf) - sizeof(*uh), 0,
		     (struct sockaddr *)&sr, &sl);
	if (n < 0)
		return;

	uh->dest = htons(ref.udp.port);
	uh->len = htons(n + sizeof(*uh));

	if (ref.udp.v6) {
		struct sockaddr_in6 *sr6 = (struct sockaddr_in6 *)&sr;

		if (IN6_IS_ADDR_LOOPBACK(&sr6->sin6_addr)) {
			in_port_t src = htons(sr6->sin6_port);

			memcpy(&sr6->sin6_addr, &c->gw6, sizeof(c->gw6));
			udp_tap_map[V6][src].ts_local = now->tv_sec;
			bitmap_set(udp_act[V6][UDP_ACT_TAP], src);
		}

		uh->source = sr6->sin6_port;

		tap_ip_send(c, &sr6->sin6_addr, IPPROTO_UDP,
			    buf, n + sizeof(*uh));
	} else {
		struct in6_addr a6 = { .s6_addr = {    0,    0,    0,    0,
						       0,    0,    0,    0,
						       0,    0, 0xff, 0xff,
						       0,    0,    0,    0 } };
		struct sockaddr_in *sr4 = (struct sockaddr_in *)&sr;

		if (ntohl(sr4->sin_addr.s_addr) == INADDR_LOOPBACK ||
		    ntohl(sr4->sin_addr.s_addr) == INADDR_ANY) {
			in_port_t src = htons(sr4->sin_port);

			sr4->sin_addr.s_addr = c->gw4;
			udp_tap_map[V4][src].ts_local = now->tv_sec;
			bitmap_set(udp_act[V4][UDP_ACT_TAP], src);
		}

		memcpy(&a6.s6_addr[12], &sr4->sin_addr, sizeof(sr4->sin_addr));

		uh->source = sr4->sin_port;

		tap_ip_send(c, &a6, IPPROTO_UDP, buf, n + sizeof(*uh));
	}
}

/**
 * udp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Destination address
 * @msg:	Input messages
 * @count:	Message count
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 */
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count, struct timespec *now)
{
	/* The caller already checks that all the messages have the same source
	 * and destination, so we can just take those from the first message.
	 */
	struct udphdr *uh = (struct udphdr *)msg[0].l4h;
	struct mmsghdr mm[UIO_MAXIOV] = { 0 };
	struct iovec m[UIO_MAXIOV];
	struct sockaddr_in6 s_in6;
	struct sockaddr_in s_in;
	struct sockaddr *sa;
	in_port_t src, dst;
	socklen_t sl;
	int i, s;

	(void)c;

	if (msg[0].l4_len < sizeof(*uh))
		return 1;

	src = ntohs(uh->source);
	dst = ntohs(uh->dest);

	if (af == AF_INET) {
		s_in = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_port = uh->dest,
			.sin_addr = *(struct in_addr *)addr,
		};

		sa = (struct sockaddr *)&s_in;
		sl = sizeof(s_in);

		if (!(s = udp_tap_map[V4][src].sock)) {
			union udp_epoll_ref uref = { .bound = 1, .port = src };

			s = sock_l4(c, AF_INET, IPPROTO_UDP, src, 0, uref.u32);
			if (s <= 0)
				return count;

			udp_tap_map[V4][src].sock = s;
			bitmap_set(udp_act[V4][UDP_ACT_TAP], src);
		}

		udp_tap_map[V4][src].ts = now->tv_sec;

		if (s_in.sin_addr.s_addr == c->gw4 &&
		    udp_tap_map[V4][dst].ts_local)
			s_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else {
		s_in6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = uh->dest,
			.sin6_addr = *(struct in6_addr *)addr,
		};

		sa = (struct sockaddr *)&s_in6;
		sl = sizeof(s_in6);

		if (!(s = udp_tap_map[V6][src].sock)) {
			union udp_epoll_ref uref = { .bound = 1, .v6 = 1,
						      .port = src
						   };

			s = sock_l4(c, AF_INET6, IPPROTO_UDP, src, 0, uref.u32);
			if (s <= 0)
				return count;

			udp_tap_map[V6][src].sock = s;
			bitmap_set(udp_act[V6][UDP_ACT_TAP], src);
		}

		udp_tap_map[V6][src].ts = now->tv_sec;

		if (!memcmp(addr, &c->gw6, sizeof(c->gw6)) &&
		    udp_tap_map[V6][dst].ts_local)
			s_in6.sin6_addr = in6addr_loopback;
	}

	for (i = 0; i < count; i++) {
		m[i].iov_base = (char *)((struct udphdr *)msg[i].l4h + 1);
		m[i].iov_len = msg[i].l4_len - sizeof(*uh);

		mm[i].msg_hdr.msg_name = sa;
		mm[i].msg_hdr.msg_namelen = sl;

		mm[i].msg_hdr.msg_iov = m + i;
		mm[i].msg_hdr.msg_iovlen = 1;
	}

	count = sendmmsg(s, mm, count, MSG_NOSIGNAL);
	if (count < 0)
		return 1;

	return count;
}

/**
 * udp_sock_init_ns() - Bind sockets in namespace for inbound connections
 * @arg:	Execution context
 *
 * Return: 0
 */
int udp_sock_init_ns(void *arg)
{
	union udp_epoll_ref uref = { .bound = 1, .splice = UDP_TO_INIT };
	struct ctx *c = (struct ctx *)arg;
	in_port_t port;

	ns_enter(c->pasta_pid);

	for (port = 0; port < USHRT_MAX; port++) {
		if (!bitmap_isset(c->udp.port_to_init, port))
			continue;

		uref.port = port;

		if (c->v4) {
			uref.v6 = 0;
			sock_l4(c, AF_INET, IPPROTO_UDP, port, 1, uref.u32);
		}

		if (c->v6) {
			uref.v6 = 1;
			sock_l4(c, AF_INET6, IPPROTO_UDP, port, 1, uref.u32);
		}
	}

	return 0;
}

/**
 * udp_splice_iov_init() - Set up buffers and descriptors for recvmmsg/sendmmsg
 */
static void udp_splice_iov_init(void)
{
	struct mmsghdr *h;
	struct iovec *iov;
	int i;

	for (i = 0, h = udp_splice_mmh_recv; i < UDP_SPLICE_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		if (!i) {
			mh->msg_name = &udp_splice_namebuf;
			mh->msg_namelen = sizeof(udp_splice_namebuf);
		}

		mh->msg_iov = &udp_splice_iov_recv[i];
		mh->msg_iovlen = 1;
	}
	for (i = 0, iov = udp_splice_iov_recv; i < UDP_SPLICE_FRAMES;
	     i++, iov++) {
		iov->iov_base = udp_splice_buf[i];
		iov->iov_len = sizeof(udp_splice_buf[i]);
	}

	for (i = 0, h = udp_splice_mmh_send; i < UDP_SPLICE_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		mh->msg_iov = &udp_splice_iov_send[i];
		mh->msg_iovlen = 1;
	}
	for (i = 0, iov = udp_splice_iov_send; i < UDP_SPLICE_FRAMES;
	     i++, iov++) {
		iov->iov_base = udp_splice_buf[i];
	}

	for (i = 0, h = udp_splice_mmh_sendto; i < UDP_SPLICE_FRAMES;
	     i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		mh->msg_name = &udp_splice_namebuf;
		mh->msg_namelen = sizeof(udp_splice_namebuf);

		mh->msg_iov = &udp_splice_iov_sendto[i];
		mh->msg_iovlen = 1;
	}
	for (i = 0, iov = udp_splice_iov_sendto; i < UDP_SPLICE_FRAMES;
	     i++, iov++) {
		iov->iov_base = udp_splice_buf[i];
	}
}

/**
 * udp_sock_init() - Create and bind listening sockets for inbound packets
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int udp_sock_init(struct ctx *c)
{
	union udp_epoll_ref uref = { .bound = 1 };
	char ns_fn_stack[NS_FN_STACK_SIZE];
	in_port_t port;
	int s;

	for (port = 0; port < USHRT_MAX; port++) {
		if (bitmap_isset(c->udp.port_to_ns, port))
			uref.splice = UDP_TO_NS;
		else if (bitmap_isset(c->udp.port_to_tap, port))
			uref.splice = 0;
		else
			continue;

		uref.port = port;

		if (c->v4) {
			uref.v6 = 0;
			s = sock_l4(c, AF_INET, IPPROTO_UDP, port,
				    uref.splice == UDP_TO_NS, uref.u32);

			if (!uref.splice && s > 0)
				udp_tap_map[V4][port].sock = s;
		}

		if (c->v6) {
			uref.v6 = 1;
			s = sock_l4(c, AF_INET6, IPPROTO_UDP, port,
				    uref.splice == UDP_TO_NS, uref.u32);

			if (!uref.splice && s > 0)
				udp_tap_map[V6][port].sock = s;
		}
	}

	if (c->mode == MODE_PASTA) {
		udp_splice_iov_init();
		clone(udp_sock_init_ns, ns_fn_stack + sizeof(ns_fn_stack) / 2,
		      CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD,
		      (void *)c);
	}

	return 0;
}

/**
 * udp_timer_one() - Handler for timed events on one port
 * @c:		Execution context
 * @v6:		Set for IPv6 connections
 * @type:	Socket type
 * @port:	Port number, host order
 * @ts:		Timestamp from caller
 */
static void udp_timer_one(struct ctx *c, int v6, enum udp_act_type type,
			  in_port_t port, struct timespec *ts)
{
	struct udp_splice_port *sp;
	struct udp_tap_port *tp;
	int s = -1;

	switch (type) {
	case UDP_ACT_TAP:
		tp = &udp_tap_map[v6 ? V6 : V4][port];

		if (ts->tv_sec - tp->ts > UDP_CONN_TIMEOUT)
			s = tp->sock;

		if (ts->tv_sec - tp->ts_local > UDP_CONN_TIMEOUT)
			tp->ts_local = 0;

		break;
	case UDP_ACT_INIT_CONN:
		sp = &udp_splice_map[v6 ? V6 : V4][port];

		if (ts->tv_sec - sp->init_conn_ts > UDP_CONN_TIMEOUT)
			s = sp->init_conn_sock;

		break;
	case UDP_ACT_NS_CONN:
		sp = &udp_splice_map[v6 ? V6 : V4][port];

		if (ts->tv_sec - sp->ns_conn_ts > UDP_CONN_TIMEOUT)
			s = sp->ns_conn_sock;

		break;
	default:
		return;
	}

	if (s != -1) {
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, s, NULL);
		close(s);
		bitmap_clear(udp_act[v6 ? V6 : V4][type], port);
	}
}

/**
 * udp_timer() - Scan activity bitmaps for ports with associated timed events
 * @c:		Execution context
 * @ts:		Timestamp from caller
 */
void udp_timer(struct ctx *c, struct timespec *ts)
{
	int n, t, v6 = 0;
	unsigned int i;
	long *word, tmp;

v6:
	for (t = 0; t < UDP_ACT_TYPE_MAX; t++) {
		word = (long *)udp_act[v6 ? V6 : V4][t];
		for (i = 0; i < sizeof(udp_act[0][0]) / sizeof(long);
		     i++, word++) {
			tmp = *word;
			while ((n = ffsl(tmp))) {
				tmp &= ~(1UL << (n - 1));
				udp_timer_one(c, v6, t,
					      i * sizeof(long) * 8 + n - 1, ts);
			}
		}
	}

	if (!v6) {
		v6 = 1;
		goto v6;
	}
}

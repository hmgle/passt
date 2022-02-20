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
 *       - connect in namespace to 127.0.0.1:80 (note: this destination port
 *         might be remapped to another port instead)
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
 *       - connect in init to 127.0.0.1:22 (note: this destination port
 *         might be remapped to another port instead)
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

#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <time.h>

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "tap.h"
#include "pcap.h"

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */
#define UDP_SPLICE_FRAMES	128
#define UDP_TAP_FRAMES		128

/**
 * struct udp_tap_port - Port tracking based on tap-facing source port
 * @sock:	Socket bound to source port used as index
 * @ts:		Activity timestamp from tap, used for socket aging
 * @ts_local:	Timestamp of tap packet to gateway address, aging for local bind
 * @loopback:	Whether local bind maps to loopback address as source
 * @gua:	Whether local bind maps to configured unicast address as source
 */
struct udp_tap_port {
	int sock;
	time_t ts;
	time_t ts_local;
	int loopback;
	int gua;
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

/* Port re-mappings as delta, indexed by original destination port */
static in_port_t		udp_port_delta_to_tap	[USHRT_MAX];
static in_port_t		udp_port_delta_from_tap	[USHRT_MAX];
static in_port_t		udp_port_delta_to_init	[USHRT_MAX];
static in_port_t		udp_port_delta_from_init[USHRT_MAX];

enum udp_act_type {
	UDP_ACT_TAP,
	UDP_ACT_NS_CONN,
	UDP_ACT_INIT_CONN,
	UDP_ACT_TYPE_MAX,
};

/* Activity-based aging for bindings */
static uint8_t udp_act[IP_VERSIONS][UDP_ACT_TYPE_MAX][USHRT_MAX / 8];

/* Static buffers */

/**
 * udp4_l2_buf_t - Pre-cooked IPv4 packet buffers for tap connections
 * @s_in:	Source socket address, filled in by recvmmsg()
 * @psum:	Partial IP header checksum (excluding tot_len and saddr)
 * @vnet_len:	4-byte qemu vnet buffer length descriptor, only for passt mode
 * @eh:		Pre-filled Ethernet header
 * @iph:	Pre-filled IP header (except for tot_len and saddr)
 * @uh:		Headroom for UDP header
 * @data:	Storage for UDP payload
 */
static struct udp4_l2_buf_t {
	struct sockaddr_in s_in;
	uint32_t psum;

	uint32_t vnet_len;
	struct ethhdr eh;
	struct iphdr iph;
	struct udphdr uh;
	uint8_t data[USHRT_MAX -
		     (sizeof(struct iphdr) + sizeof(struct udphdr))];
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
udp4_l2_buf[UDP_TAP_FRAMES];

/**
 * udp6_l2_buf_t - Pre-cooked IPv6 packet buffers for tap connections
 * @s_in6:	Source socket address, filled in by recvmmsg()
 * @vnet_len:	4-byte qemu vnet buffer length descriptor, only for passt mode
 * @eh:		Pre-filled Ethernet header
 * @ip6h:	Pre-filled IP header (except for payload_len and addresses)
 * @uh:		Headroom for UDP header
 * @data:	Storage for UDP payload
 */
struct udp6_l2_buf_t {
	struct sockaddr_in6 s_in6;
#ifdef __AVX2__
	/* Align ip6h to 32-byte boundary. */
	uint8_t pad[64 - (sizeof(struct sockaddr_in6) + sizeof(struct ethhdr) +
			  sizeof(uint32_t))];
#endif

	uint32_t vnet_len;
	struct ethhdr eh;
	struct ipv6hdr ip6h;
	struct udphdr uh;
	uint8_t data[USHRT_MAX -
		     (sizeof(struct ipv6hdr) + sizeof(struct udphdr))];
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
udp6_l2_buf[UDP_TAP_FRAMES];

static struct sockaddr_storage udp_splice_namebuf;
static uint8_t udp_splice_buf[UDP_SPLICE_FRAMES][USHRT_MAX];

/* recvmmsg()/sendmmsg() data for tap */
static struct iovec	udp4_l2_iov_sock	[UDP_TAP_FRAMES];
static struct iovec	udp6_l2_iov_sock	[UDP_TAP_FRAMES];

static struct iovec	udp4_l2_iov_tap		[UDP_TAP_FRAMES];
static struct iovec	udp6_l2_iov_tap		[UDP_TAP_FRAMES];

static struct mmsghdr	udp4_l2_mh_sock		[UDP_TAP_FRAMES];
static struct mmsghdr	udp6_l2_mh_sock		[UDP_TAP_FRAMES];

static struct mmsghdr	udp4_l2_mh_tap		[UDP_TAP_FRAMES];
static struct mmsghdr	udp6_l2_mh_tap		[UDP_TAP_FRAMES];

/* recvmmsg()/sendmmsg() data for "spliced" connections */
static struct iovec	udp_splice_iov_recv	[UDP_SPLICE_FRAMES];
static struct mmsghdr	udp_splice_mmh_recv	[UDP_SPLICE_FRAMES];

static struct iovec	udp_splice_iov_send	[UDP_SPLICE_FRAMES];
static struct mmsghdr	udp_splice_mmh_send	[UDP_SPLICE_FRAMES];

static struct iovec	udp_splice_iov_sendto	[UDP_SPLICE_FRAMES];
static struct mmsghdr	udp_splice_mmh_sendto	[UDP_SPLICE_FRAMES];

/**
 * udp_remap_to_tap() - Set delta for port translation to/from guest/tap
 * @port:	Original destination port, host order
 * @delta:	Delta to be added to original destination port
 */
void udp_remap_to_tap(in_port_t port, in_port_t delta)
{
	udp_port_delta_to_tap[port] = delta;
	udp_port_delta_from_tap[port + delta] = USHRT_MAX - delta;
}

/**
 * udp_remap_to_init() - Set delta for port translation to/from init namespace
 * @port:	Original destination port, host order
 * @delta:	Delta to be added to original destination port
 */
void udp_remap_to_init(in_port_t port, in_port_t delta)
{
	udp_port_delta_to_init[port] = delta;
	udp_port_delta_from_init[port + delta] = USHRT_MAX - delta;
}

/**
 * udp_update_check4() - Update checksum with variable parts from stored one
 * @buf:	L2 packet buffer with final IPv4 header
 */
static void udp_update_check4(struct udp4_l2_buf_t *buf)
{
	uint32_t sum = buf->psum;

	sum += buf->iph.tot_len;
	sum += (buf->iph.saddr >> 16) & 0xffff;
	sum += buf->iph.saddr & 0xffff;

	buf->iph.check = (uint16_t)~csum_fold(sum);
}

/**
 * udp_update_l2_buf() - Update L2 buffers with Ethernet and IPv4 addresses
 * @eth_d:	Ethernet destination address, NULL if unchanged
 * @eth_s:	Ethernet source address, NULL if unchanged
 * @ip_da:	Pointer to IPv4 destination address, NULL if unchanged
 */
void udp_update_l2_buf(unsigned char *eth_d, unsigned char *eth_s,
		       const uint32_t *ip_da)
{
	int i;

	for (i = 0; i < UDP_TAP_FRAMES; i++) {
		struct udp4_l2_buf_t *b4 = &udp4_l2_buf[i];
		struct udp6_l2_buf_t *b6 = &udp6_l2_buf[i];

		if (eth_d) {
			memcpy(b4->eh.h_dest, eth_d, ETH_ALEN);
			memcpy(b6->eh.h_dest, eth_d, ETH_ALEN);
		}

		if (eth_s) {
			memcpy(b4->eh.h_source, eth_s, ETH_ALEN);
			memcpy(b6->eh.h_source, eth_s, ETH_ALEN);
		}

		if (ip_da) {
			b4->iph.daddr = *ip_da;
			if (!i) {
				b4->iph.saddr = 0;
				b4->iph.tot_len = 0;
				b4->iph.check = 0;
				b4->psum = sum_16b(&b4->iph, 20);
			} else {
				b4->psum = udp4_l2_buf[0].psum;
			}
		}
	}
}

/**
 * udp_sock4_iov_init() - Initialise scatter-gather L2 buffers for IPv4 sockets
 */
static void udp_sock4_iov_init(void)
{
	struct mmsghdr *h;
	int i;

	for (i = 0; i < ARRAY_SIZE(udp4_l2_buf); i++) {
		udp4_l2_buf[i] = (struct udp4_l2_buf_t) {
			{ 0 }, 0, 0,
			L2_BUF_ETH_IP4_INIT, L2_BUF_IP4_INIT(IPPROTO_UDP),
			{{{ 0 }}}, { 0 },
		};
	}

	for (i = 0, h = udp4_l2_mh_sock; i < UDP_TAP_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		mh->msg_name			= &udp4_l2_buf[i].s_in;
		mh->msg_namelen			= sizeof(udp4_l2_buf[i].s_in);

		udp4_l2_iov_sock[i].iov_base	= udp4_l2_buf[i].data;
		udp4_l2_iov_sock[i].iov_len	= sizeof(udp4_l2_buf[i].data);
		mh->msg_iov			= &udp4_l2_iov_sock[i];
		mh->msg_iovlen			= 1;
	}

	for (i = 0, h = udp4_l2_mh_tap; i < UDP_TAP_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		udp4_l2_iov_tap[i].iov_base	= &udp4_l2_buf[i].vnet_len;
		mh->msg_iov			= &udp4_l2_iov_tap[i];
		mh->msg_iovlen			= 1;
	}
}

/**
 * udp_sock6_iov_init() - Initialise scatter-gather L2 buffers for IPv6 sockets
 */
static void udp_sock6_iov_init(void)
{
	struct mmsghdr *h;
	int i;

	for (i = 0; i < ARRAY_SIZE(udp6_l2_buf); i++) {
		udp6_l2_buf[i] = (struct udp6_l2_buf_t) {
			{ 0 },
#ifdef __AVX2__
			{ 0 },
#endif
			0, L2_BUF_ETH_IP6_INIT, L2_BUF_IP6_INIT(IPPROTO_UDP),
			{{{ 0 }}}, { 0 },
		};
	}

	for (i = 0, h = udp6_l2_mh_sock; i < UDP_TAP_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		mh->msg_name			= &udp6_l2_buf[i].s_in6;
		mh->msg_namelen			= sizeof(struct sockaddr_in6);

		udp6_l2_iov_sock[i].iov_base	= udp6_l2_buf[i].data;
		udp6_l2_iov_sock[i].iov_len	= sizeof(udp6_l2_buf[i].data);
		mh->msg_iov			= &udp6_l2_iov_sock[i];
		mh->msg_iovlen			= 1;
	}

	for (i = 0, h = udp6_l2_mh_tap; i < UDP_TAP_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		udp6_l2_iov_tap[i].iov_base	= &udp6_l2_buf[i].vnet_len;
		mh->msg_iov			= &udp6_l2_iov_tap[i];
		mh->msg_iovlen			= 1;
	}
}

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
 *
 * #syscalls:pasta getsockname
 */
int udp_splice_connect(struct ctx *c, int v6, int bound_sock,
		       in_port_t src, in_port_t dst, int splice)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLHUP };
	union epoll_ref ref = { .r.proto = IPPROTO_UDP,
				.r.p.udp.udp = { .splice = splice, .v6 = v6 }
			      };
	struct sockaddr_storage sa;
	struct udp_splice_port *sp;
	socklen_t sl = sizeof(sa);
	int s;

	s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK,
		   IPPROTO_UDP);
	if (s < 0)
		return s;
	ref.r.s = s;

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

	if (v6) {
		struct sockaddr_in6 sa6;

		memcpy(&sa6, &sa, sizeof(sa6));
		ref.r.p.udp.udp.port = ntohs(sa6.sin6_port);
	} else {
		struct sockaddr_in sa4;

		memcpy(&sa4, &sa, sizeof(sa4));
		ref.r.p.udp.udp.port = ntohs(sa4.sin_port);
	}

	sp = &udp_splice_map[v6 ? V6 : V4][ref.r.p.udp.udp.port];
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

	if (ns_enter(a->c))
		return 0;

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
	in_port_t src, dst = ref.r.p.udp.udp.port, send_dst = 0;
	struct msghdr *mh = &udp_splice_mmh_recv[0].msg_hdr;
	struct sockaddr_storage *sa_s = mh->msg_name;
	int s, v6 = ref.r.p.udp.udp.v6, n, i;

	if (!(events & EPOLLIN))
		return;

	n = recvmmsg(ref.r.s, udp_splice_mmh_recv, UDP_SPLICE_FRAMES, 0, NULL);

	if (n <= 0)
		return;

	if (v6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)sa_s;

		src = htons(sa->sin6_port);
	} else {
		struct sockaddr_in *sa = (struct sockaddr_in *)sa_s;

		src = ntohs(sa->sin_port);
	}

	switch (ref.r.p.udp.udp.splice) {
	case UDP_TO_NS:
		src += udp_port_delta_from_init[src];

		if (!(s = udp_splice_map[v6][src].ns_conn_sock)) {
			struct udp_splice_connect_ns_arg arg = {
				c, v6, ref.r.s, src, dst, -1,
			};

			NS_CALL(udp_splice_connect_ns, &arg);
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
		src += udp_port_delta_from_tap[src];

		if (!(s = udp_splice_map[v6][src].init_conn_sock)) {
			s = udp_splice_connect(c, v6, ref.r.s, src, dst,
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

	if (ref.r.p.udp.udp.splice == UDP_TO_NS ||
	    ref.r.p.udp.udp.splice == UDP_TO_INIT) {
		for (i = 0; i < n; i++) {
			struct msghdr *mh_s = &udp_splice_mmh_send[i].msg_hdr;

			mh_s->msg_iov->iov_len = udp_splice_mmh_recv[i].msg_len;
		}

		sendmmsg(s, udp_splice_mmh_send, n, MSG_NOSIGNAL);
		return;
	}

	for (i = 0; i < n; i++) {
		struct msghdr *mh_s = &udp_splice_mmh_sendto[i].msg_hdr;

		mh_s->msg_iov->iov_len = udp_splice_mmh_recv[i].msg_len;
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
 *
 * #syscalls recvmmsg
 * #syscalls:passt sendmmsg sendmsg
 */
void udp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      struct timespec *now)
{
	int iov_in_msg, msg_i = 0, ret;
	ssize_t n, msglen, missing = 0;
	struct mmsghdr *tap_mmh;
	struct msghdr *cur_mh;
	unsigned int i;

	if (events == EPOLLERR)
		return;

	if (ref.r.p.udp.udp.splice) {
		udp_sock_handler_splice(c, ref, events, now);
		return;
	}

	if (ref.r.p.udp.udp.v6) {
		n = recvmmsg(ref.r.s, udp6_l2_mh_sock, UDP_TAP_FRAMES, 0, NULL);
		if (n <= 0)
			return;

		cur_mh = &udp6_l2_mh_tap[msg_i].msg_hdr;
		cur_mh->msg_iov = &udp6_l2_iov_tap[0];
		msg_i = msglen = iov_in_msg = 0;

		for (i = 0; i < (unsigned)n; i++) {
			struct udp6_l2_buf_t *b = &udp6_l2_buf[i];
			size_t ip_len, iov_len;

			ip_len = udp6_l2_mh_sock[i].msg_len +
				 sizeof(b->ip6h) + sizeof(b->uh);

			b->ip6h.payload_len = htons(udp6_l2_mh_sock[i].msg_len +
						    sizeof(b->uh));

			if (IN6_IS_ADDR_LINKLOCAL(&b->s_in6.sin6_addr)) {
				b->ip6h.daddr = c->addr6_ll_seen;
				b->ip6h.saddr = b->s_in6.sin6_addr;
			} else if (IN6_IS_ADDR_LOOPBACK(&b->s_in6.sin6_addr) ||
				   !memcmp(&b->s_in6.sin6_addr, &c->addr6_seen,
					   sizeof(c->addr6)) ||
				   !memcmp(&b->s_in6.sin6_addr, &c->addr6,
					   sizeof(c->addr6))) {
				in_port_t src = htons(b->s_in6.sin6_port);

				b->ip6h.daddr = c->addr6_ll_seen;

				if (IN6_IS_ADDR_LINKLOCAL(&c->gw6))
					b->ip6h.saddr = c->gw6;
				else
					b->ip6h.saddr = c->addr6_ll;

				udp_tap_map[V6][src].ts_local = now->tv_sec;

				if (IN6_IS_ADDR_LOOPBACK(&b->s_in6.sin6_addr))
					udp_tap_map[V6][src].loopback = 1;
				else
					udp_tap_map[V6][src].loopback = 0;

				if (!memcmp(&b->s_in6.sin6_addr, &c->addr6,
						 sizeof(c->addr6)))
					udp_tap_map[V6][src].gua = 1;
				else
					udp_tap_map[V6][src].gua = 0;

				bitmap_set(udp_act[V6][UDP_ACT_TAP], src);
			} else if (!IN6_IS_ADDR_UNSPECIFIED(&c->dns6_fwd) &&
				   !memcmp(&b->s_in6.sin6_addr, &c->dns6_fwd,
					   sizeof(c->dns6_fwd)) &&
				   ntohs(b->s_in6.sin6_port) == 53) {
				b->ip6h.daddr = c->addr6_seen;
				b->ip6h.saddr = c->dns6_fwd;
			} else {
				b->ip6h.daddr = c->addr6_seen;
				b->ip6h.saddr = b->s_in6.sin6_addr;
			}

			b->uh.source = b->s_in6.sin6_port;
			b->uh.dest = htons(ref.r.p.udp.udp.port);
			b->uh.len = b->ip6h.payload_len;

			b->ip6h.hop_limit = IPPROTO_UDP;
			b->ip6h.version = 0;
			b->ip6h.nexthdr = 0;
			b->uh.check = 0;
			b->uh.check = csum(&b->ip6h, ip_len, 0);
			b->ip6h.version = 6;
			b->ip6h.nexthdr = IPPROTO_UDP;
			b->ip6h.hop_limit = 255;

			if (c->mode == MODE_PASTA) {
				ip_len += sizeof(struct ethhdr);
				if (write(c->fd_tap, &b->eh, ip_len) < 0)
					debug("tap write: %s", strerror(errno));
				pcap((char *)&b->eh, ip_len);
				continue;
			}

			b->vnet_len = htonl(ip_len + sizeof(struct ethhdr));
			iov_len = sizeof(uint32_t) + sizeof(struct ethhdr) +
				  ip_len;
			udp6_l2_iov_tap[i].iov_len = iov_len;

			/* With bigger messages, qemu closes the connection. */
			if (iov_in_msg && msglen + iov_len > SHRT_MAX) {
				cur_mh->msg_iovlen = iov_in_msg;

				cur_mh = &udp6_l2_mh_tap[++msg_i].msg_hdr;
				msglen = iov_in_msg = 0;
				cur_mh->msg_iov = &udp6_l2_iov_tap[i];
			}

			msglen += iov_len;
			iov_in_msg++;
		}

		tap_mmh = udp6_l2_mh_tap;
	} else {
		n = recvmmsg(ref.r.s, udp4_l2_mh_sock, UDP_TAP_FRAMES, 0, NULL);
		if (n <= 0)
			return;

		cur_mh = &udp4_l2_mh_tap[msg_i].msg_hdr;
		cur_mh->msg_iov = &udp4_l2_iov_tap[0];
		msg_i = msglen = iov_in_msg = 0;

		for (i = 0; i < (unsigned)n; i++) {
			struct udp4_l2_buf_t *b = &udp4_l2_buf[i];
			size_t ip_len, iov_len;
			in_addr_t s_addr;

			ip_len = udp4_l2_mh_sock[i].msg_len +
				 sizeof(b->iph) + sizeof(b->uh);

			b->iph.tot_len = htons(ip_len);

			s_addr = ntohl(b->s_in.sin_addr.s_addr);
			if (s_addr >> IN_CLASSA_NSHIFT == IN_LOOPBACKNET ||
			    s_addr == INADDR_ANY ||
			    s_addr == ntohl(c->addr4_seen)) {
				in_port_t src = htons(b->s_in.sin_port);

				b->iph.saddr = c->gw4;
				udp_tap_map[V4][src].ts_local = now->tv_sec;

				if (b->s_in.sin_addr.s_addr == c->addr4_seen)
					udp_tap_map[V4][src].loopback = 0;
				else
					udp_tap_map[V4][src].loopback = 1;

				bitmap_set(udp_act[V4][UDP_ACT_TAP], src);
			} else if (c->dns4_fwd &&
				   s_addr == ntohl(c->dns4[0]) &&
				   ntohs(b->s_in.sin_port) == 53) {
				b->iph.saddr = c->dns4_fwd;
			} else {
				b->iph.saddr = b->s_in.sin_addr.s_addr;
			}

			udp_update_check4(b);
			b->uh.source = b->s_in.sin_port;
			b->uh.dest = htons(ref.r.p.udp.udp.port);
			b->uh.len = ntohs(udp4_l2_mh_sock[i].msg_len +
					  sizeof(b->uh));

			if (c->mode == MODE_PASTA) {
				ip_len += sizeof(struct ethhdr);
				if (write(c->fd_tap, &b->eh, ip_len) < 0)
					debug("tap write: %s", strerror(errno));
				pcap((char *)&b->eh, ip_len);
				continue;
			}

			b->vnet_len = htonl(ip_len + sizeof(struct ethhdr));
			iov_len = sizeof(uint32_t) + sizeof(struct ethhdr) +
				  ip_len;
			udp4_l2_iov_tap[i].iov_len = iov_len;

			/* With bigger messages, qemu closes the connection. */
			if (iov_in_msg && msglen + iov_len > SHRT_MAX) {
				cur_mh->msg_iovlen = iov_in_msg;

				cur_mh = &udp4_l2_mh_tap[++msg_i].msg_hdr;
				msglen = iov_in_msg = 0;
				cur_mh->msg_iov = &udp4_l2_iov_tap[i];
			}

			msglen += iov_len;
			iov_in_msg++;
		}

		tap_mmh = udp4_l2_mh_tap;
	}

	if (c->mode == MODE_PASTA)
		return;

	cur_mh->msg_iovlen = iov_in_msg;
	ret = sendmmsg(c->fd_tap, tap_mmh, msg_i + 1,
		       MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret <= 0)
		return;

	/* If we lose some messages to sendmmsg() here, fine, it's UDP. However,
	 * the last message needs to be delivered completely, otherwise qemu
	 * will fail to reassemble the next message and close the connection. Go
	 * through headers from the last sent message, counting bytes, and, if
	 * and as soon as we see more bytes than sendmmsg() sent, re-send the
	 * rest with a blocking call.
	 *
	 * In pictures, given this example:
	 *
	 *				 	iov #0  iov #1  iov #2  iov #3
	 * tap_mmh[ret - 1].msg_hdr:		....    ......  .....   ......
	 * tap_mmh[ret - 1].msg_len:	7	....    ...
	 *
	 * when 'msglen' reaches:	10		      ^
	 * and 'missing' below is:	3	           ---
	 *
	 * re-send everything from here:		   ^--  -----   ------
	 */
	cur_mh = &tap_mmh[ret - 1].msg_hdr;
	for (i = 0, msglen = 0; i < cur_mh->msg_iovlen; i++) {
		if (missing <= 0) {
			msglen += cur_mh->msg_iov[i].iov_len;
			missing = msglen - tap_mmh[ret - 1].msg_len;
		}

		if (missing > 0) {
			uint8_t **iov_base;
			int first_offset;

			iov_base = (uint8_t **)&cur_mh->msg_iov[i].iov_base;
			first_offset = cur_mh->msg_iov[i].iov_len - missing;
			*iov_base += first_offset;
			cur_mh->msg_iov[i].iov_len = missing;

			cur_mh->msg_iov = &cur_mh->msg_iov[i];

			sendmsg(c->fd_tap, cur_mh, MSG_NOSIGNAL);

			*iov_base -= first_offset;
			break;
		}
	}

	pcapmm(tap_mmh, ret);
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
 *
 * #syscalls sendmmsg
 */
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_l4_msg *msg, int count, struct timespec *now)
{
	/* The caller already checks that all the messages have the same source
	 * and destination, so we can just take those from the first message.
	 */
	struct udphdr *uh = (struct udphdr *)(pkt_buf + msg[0].pkt_buf_offset);
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
			union udp_epoll_ref uref = { .udp.bound = 1,
						     .udp.port = src };

			s = sock_l4(c, AF_INET, IPPROTO_UDP, src, 0, uref.u32);
			if (s <= 0)
				return count;

			udp_tap_map[V4][src].sock = s;
			bitmap_set(udp_act[V4][UDP_ACT_TAP], src);
		}

		udp_tap_map[V4][src].ts = now->tv_sec;

		if (s_in.sin_addr.s_addr == c->gw4 && !c->no_map_gw) {
			if (!udp_tap_map[V4][dst].ts_local ||
			    udp_tap_map[V4][dst].loopback)
				s_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			else
				s_in.sin_addr.s_addr = c->addr4_seen;
		} else if (s_in.sin_addr.s_addr == c->dns4_fwd &&
			   ntohs(s_in.sin_port) == 53) {
			s_in.sin_addr.s_addr = c->dns4[0];
		}
	} else {
		s_in6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = uh->dest,
			.sin6_addr = *(struct in6_addr *)addr,
		};
		enum bind_type bind_to = BIND_ANY;

		sa = (struct sockaddr *)&s_in6;
		sl = sizeof(s_in6);

		if (!memcmp(addr, &c->gw6, sizeof(c->gw6)) && !c->no_map_gw) {
			if (!udp_tap_map[V6][dst].ts_local ||
			    udp_tap_map[V6][dst].loopback)
				s_in6.sin6_addr = in6addr_loopback;
			else if (udp_tap_map[V6][dst].gua)
				s_in6.sin6_addr = c->addr6;
			else
				s_in6.sin6_addr = c->addr6_seen;
		} else if (!memcmp(addr, &c->dns6_fwd, sizeof(c->dns6_fwd)) &&
			   ntohs(s_in6.sin6_port) == 53) {
			s_in6.sin6_addr = c->dns6[0];
		} else if (IN6_IS_ADDR_LINKLOCAL(&s_in6.sin6_addr)) {
			bind_to = BIND_LL;
		}

		if (!(s = udp_tap_map[V6][src].sock)) {
			union udp_epoll_ref uref = { .udp.bound = 1,
						     .udp.v6 = 1,
						     .udp.port = src };

			s = sock_l4(c, AF_INET6, IPPROTO_UDP, src, bind_to,
				    uref.u32);
			if (s <= 0)
				return count;

			udp_tap_map[V6][src].sock = s;
			bitmap_set(udp_act[V6][UDP_ACT_TAP], src);
		}

		udp_tap_map[V6][src].ts = now->tv_sec;
	}

	for (i = 0; i < count; i++) {
		struct udphdr *uh_send;

		uh_send = (struct udphdr *)(msg[i].pkt_buf_offset + pkt_buf);
		m[i].iov_base = (char *)(uh_send + 1);
		m[i].iov_len = msg[i].l4_len - sizeof(*uh_send);

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
	union udp_epoll_ref uref = { .udp.bound = 1,
				     .udp.splice = UDP_TO_INIT };
	struct ctx *c = (struct ctx *)arg;
	int dst;

	if (ns_enter(c))
		return 0;

	for (dst = 0; dst < USHRT_MAX; dst++) {
		if (!bitmap_isset(c->udp.port_to_init, dst))
			continue;

		uref.udp.port = dst + udp_port_delta_to_init[dst];

		if (c->v4) {
			uref.udp.v6 = 0;
			sock_l4(c, AF_INET, IPPROTO_UDP, dst, BIND_LOOPBACK,
				uref.u32);
		}

		if (c->v6) {
			uref.udp.v6 = 1;
			sock_l4(c, AF_INET6, IPPROTO_UDP, dst, BIND_LOOPBACK,
				uref.u32);
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
int udp_sock_init(struct ctx *c, struct timespec *now)
{
	union udp_epoll_ref uref = { .udp.bound = 1 };
	int dst, s;

	(void)now;

	for (dst = 0; dst < USHRT_MAX; dst++) {
		if (!bitmap_isset(c->udp.port_to_tap, dst))
			continue;

		uref.udp.port = dst + udp_port_delta_to_tap[dst];

		if (c->v4) {
			uref.udp.splice = 0;
			uref.udp.v6 = 0;
			s = sock_l4(c, AF_INET, IPPROTO_UDP, dst,
				    c->mode == MODE_PASTA ? BIND_EXT : BIND_ANY,
				    uref.u32);
			if (s > 0)
				udp_tap_map[V4][uref.udp.port].sock = s;

			if (c->mode == MODE_PASTA) {
				uref.udp.splice = UDP_TO_NS;
				sock_l4(c, AF_INET, IPPROTO_UDP, dst,
					BIND_LOOPBACK, uref.u32);
			}
		}
		if (c->v6) {
			uref.udp.splice = 0;
			uref.udp.v6 = 1;
			s = sock_l4(c, AF_INET6, IPPROTO_UDP, dst,
				    c->mode == MODE_PASTA ? BIND_EXT : BIND_ANY,
				    uref.u32);
			if (s > 0)
				udp_tap_map[V6][uref.udp.port].sock = s;

			if (c->mode == MODE_PASTA) {
				uref.udp.splice = UDP_TO_NS;
				sock_l4(c, AF_INET6, IPPROTO_UDP, dst,
					BIND_LOOPBACK, uref.u32);
			}
		}
	}

	if (c->v4)
		udp_sock4_iov_init();

	if (c->v6)
		udp_sock6_iov_init();

	if (c->mode == MODE_PASTA) {
		udp_splice_iov_init();
		NS_CALL(udp_sock_init_ns, c);
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

		if (ts->tv_sec - tp->ts_local > UDP_CONN_TIMEOUT) {
			tp->ts_local = 0;
			tp->loopback = 0;
			tp->gua = 0;
		}

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

	if (s > 0) {
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

	if (!c->v4)
		v6 = 1;
v6:
	for (t = 0; t < UDP_ACT_TYPE_MAX; t++) {
		word = (long *)udp_act[v6 ? V6 : V4][t];
		for (i = 0; i < ARRAY_SIZE(udp_act[0][0]);
		     i += sizeof(long), word++) {
			tmp = *word;
			while ((n = ffsl(tmp))) {
				tmp &= ~(1UL << (n - 1));
				udp_timer_one(c, v6, t, i * 8 + n - 1, ts);
			}
		}
	}

	if (!v6 && c->v6) {
		v6 = 1;
		goto v6;
	}
}

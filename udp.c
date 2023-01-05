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
 *   - forward direction: 127.0.0.1:5000 -> 127.0.0.1:80 in init from socket s,
 *     with epoll reference: index = 80, splice = 1, orig = 1, ns = 0
 *     - if udp_splice_ns[V4][5000].sock:
 *       - send packet to udp_splice_ns[V4][5000].sock, with destination port
 *         80
 *     - otherwise:
 *       - create new socket udp_splice_ns[V4][5000].sock
 *       - bind in namespace to 127.0.0.1:5000
 *       - add to epoll with reference: index = 5000, splice = 1, orig = 0,
 *         ns = 1
 *     - update udp_splice_init[V4][80].ts and udp_splice_ns[V4][5000].ts with
 *       current time
 *
 *   - reverse direction: 127.0.0.1:80 -> 127.0.0.1:5000 in namespace socket s,
 *     having epoll reference: index = 5000, splice = 1, orig = 0, ns = 1
 *     - if udp_splice_init[V4][80].sock:
 *       - send to udp_splice_init[V4][80].sock, with destination port 5000
 *       - update udp_splice_init[V4][80].ts and udp_splice_ns[V4][5000].ts with
 *         current time
 *     - otherwise, discard
 *
 * - from namespace to init:
 *
 *   - forward direction: 127.0.0.1:2000 -> 127.0.0.1:22 in namespace from
 *     socket s, with epoll reference: index = 22, splice = 1, orig = 1, ns = 1
 *     - if udp4_splice_init[V4][2000].sock:
 *       - send packet to udp_splice_init[V4][2000].sock, with destination
 *         port 22
 *     - otherwise:
 *       - create new socket udp_splice_init[V4][2000].sock
 *       - bind in init to 127.0.0.1:2000
 *       - add to epoll with reference: index = 2000, splice = 1, orig = 0,
 *         ns = 0
 *     - update udp_splice_ns[V4][22].ts and udp_splice_init[V4][2000].ts with
 *       current time
 *
 *   - reverse direction: 127.0.0.1:22 -> 127.0.0.1:2000 in init from socket s,
 *     having epoll reference: index = 2000, splice = 1, orig = 0, ns = 0
 *   - if udp_splice_ns[V4][22].sock:
 *     - send to udp_splice_ns[V4][22].sock, with destination port 2000
 *     - update udp_splice_ns[V4][22].ts and udp_splice_init[V4][2000].ts with
 *       current time
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
#include <assert.h>

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "tap.h"
#include "pcap.h"
#include "log.h"

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */
#define UDP_MAX_FRAMES		32  /* max # of frames to receive at once */
#define UDP_TAP_FRAMES		(c->mode == MODE_PASST ? UDP_MAX_FRAMES : 1)

/**
 * struct udp_tap_port - Port tracking based on tap-facing source port
 * @sock:	Socket bound to source port used as index
 * @flags:	Flags for local bind, loopback address/unicast address as source
 * @ts:		Activity timestamp from tap, used for socket aging
 */
struct udp_tap_port {
	int sock;
	uint8_t flags;
#define PORT_LOCAL	BIT(0)
#define PORT_LOOPBACK	BIT(1)
#define PORT_GUA	BIT(2)

	time_t ts;
};

/**
 * struct udp_splice_port - Bound socket for spliced communication
 * @sock:	Socket bound to index port
 * @ts:		Activity timestamp
 */
struct udp_splice_port {
	int sock;
	time_t ts;
};

/* Port tracking, arrays indexed by packet source port (host order) */
static struct udp_tap_port	udp_tap_map	[IP_VERSIONS][NUM_PORTS];

/* "Spliced" sockets indexed by bound port (host order) */
static struct udp_splice_port udp_splice_ns  [IP_VERSIONS][NUM_PORTS];
static struct udp_splice_port udp_splice_init[IP_VERSIONS][NUM_PORTS];

enum udp_act_type {
	UDP_ACT_TAP,
	UDP_ACT_SPLICE_NS,
	UDP_ACT_SPLICE_INIT,
	UDP_ACT_TYPE_MAX,
};

/* Activity-based aging for bindings */
static uint8_t udp_act[IP_VERSIONS][UDP_ACT_TYPE_MAX][DIV_ROUND_UP(NUM_PORTS, 8)];

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
udp4_l2_buf[UDP_MAX_FRAMES];

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
udp6_l2_buf[UDP_MAX_FRAMES];

/* recvmmsg()/sendmmsg() data for tap */
static struct iovec	udp4_l2_iov_sock	[UDP_MAX_FRAMES];
static struct iovec	udp6_l2_iov_sock	[UDP_MAX_FRAMES];

static struct iovec	udp4_l2_iov_tap		[UDP_MAX_FRAMES];
static struct iovec	udp6_l2_iov_tap		[UDP_MAX_FRAMES];

static struct mmsghdr	udp4_l2_mh_sock		[UDP_MAX_FRAMES];
static struct mmsghdr	udp6_l2_mh_sock		[UDP_MAX_FRAMES];

static struct mmsghdr	udp4_l2_mh_tap		[UDP_MAX_FRAMES];
static struct mmsghdr	udp6_l2_mh_tap		[UDP_MAX_FRAMES];

/* recvmmsg()/sendmmsg() data for "spliced" connections */
static struct sockaddr_storage udp_splice_namebuf;

static struct iovec	udp4_iov_splice		[UDP_MAX_FRAMES];
static struct iovec	udp6_iov_splice		[UDP_MAX_FRAMES];

static struct mmsghdr	udp4_mh_splice		[UDP_MAX_FRAMES];
static struct mmsghdr	udp6_mh_splice		[UDP_MAX_FRAMES];

/**
 * udp_invert_portmap() - Compute reverse port translations for return packets
 * @fwd:	Port forwarding configuration to compute reverse map for
 */
static void udp_invert_portmap(struct udp_port_fwd *fwd)
{
	int i;

	assert(ARRAY_SIZE(fwd->f.delta) == ARRAY_SIZE(fwd->rdelta));
	for (i = 0; i < ARRAY_SIZE(fwd->f.delta); i++) {
		in_port_t delta = fwd->f.delta[i];

		if (delta)
			fwd->rdelta[(in_port_t)i + delta] = NUM_PORTS - delta;
	}
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
void udp_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s,
		       const struct in_addr *ip_da)
{
	int i;

	for (i = 0; i < UDP_MAX_FRAMES; i++) {
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
			b4->iph.daddr = ip_da->s_addr;
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
 * @c:		Execution context
 */
static void udp_sock4_iov_init(const struct ctx *c)
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

	for (i = 0, h = udp4_l2_mh_sock; i < UDP_MAX_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		mh->msg_name			= &udp4_l2_buf[i].s_in;
		mh->msg_namelen			= sizeof(udp4_l2_buf[i].s_in);

		udp4_l2_iov_sock[i].iov_base	= udp4_l2_buf[i].data;
		udp4_l2_iov_sock[i].iov_len	= sizeof(udp4_l2_buf[i].data);
		mh->msg_iov			= &udp4_l2_iov_sock[i];
		mh->msg_iovlen			= 1;
	}

	for (i = 0, h = udp4_l2_mh_tap; i < UDP_MAX_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		if (c->mode == MODE_PASTA)
			udp4_l2_iov_tap[i].iov_base	= &udp4_l2_buf[i].eh;
		else
			udp4_l2_iov_tap[i].iov_base	= &udp4_l2_buf[i].vnet_len;

		mh->msg_iov			= &udp4_l2_iov_tap[i];
		mh->msg_iovlen			= 1;
	}
}

/**
 * udp_sock6_iov_init() - Initialise scatter-gather L2 buffers for IPv6 sockets
 * @c:		Execution context
 */
static void udp_sock6_iov_init(const struct ctx *c)
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

	for (i = 0, h = udp6_l2_mh_sock; i < UDP_MAX_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		mh->msg_name			= &udp6_l2_buf[i].s_in6;
		mh->msg_namelen			= sizeof(struct sockaddr_in6);

		udp6_l2_iov_sock[i].iov_base	= udp6_l2_buf[i].data;
		udp6_l2_iov_sock[i].iov_len	= sizeof(udp6_l2_buf[i].data);
		mh->msg_iov			= &udp6_l2_iov_sock[i];
		mh->msg_iovlen			= 1;
	}

	for (i = 0, h = udp6_l2_mh_tap; i < UDP_MAX_FRAMES; i++, h++) {
		struct msghdr *mh = &h->msg_hdr;

		if (c->mode == MODE_PASTA)
			udp6_l2_iov_tap[i].iov_base	= &udp6_l2_buf[i].eh;
		else
			udp6_l2_iov_tap[i].iov_base	= &udp6_l2_buf[i].vnet_len;

		mh->msg_iov			= &udp6_l2_iov_tap[i];
		mh->msg_iovlen			= 1;
	}
}

/**
 * udp_splice_new() - Create and prepare socket for "spliced" binding
 * @c:		Execution context
 * @v6:		Set for IPv6 sockets
 * @src:	Source port of original connection, host order
 * @splice:	UDP_BACK_TO_INIT from init, UDP_BACK_TO_NS from namespace
 *
 * Return: prepared socket, negative error code on failure
 *
 * #syscalls:pasta getsockname
 */
int udp_splice_new(const struct ctx *c, int v6, in_port_t src, bool ns)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLHUP };
	union epoll_ref ref = { .r.proto = IPPROTO_UDP,
				.r.p.udp.udp = { .splice = true, .ns = ns,
						 .v6 = v6, .port = src }
			      };
	struct udp_splice_port *sp;
	int act, s;

	if (ns) {
		sp = &udp_splice_ns[v6 ? V6 : V4][src];
		act = UDP_ACT_SPLICE_NS;
	} else {
		sp = &udp_splice_init[v6 ? V6 : V4][src];
		act = UDP_ACT_SPLICE_INIT;
	}

	s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK,
		   IPPROTO_UDP);

	if (s > SOCKET_MAX) {
		close(s);
		return -EIO;
	}

	if (s < 0)
		return s;

	ref.r.s = s;

	if (v6) {
		struct sockaddr_in6 addr6 = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(src),
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		};
		if (bind(s, (struct sockaddr *)&addr6, sizeof(addr6)))
			goto fail;
	} else {
		struct sockaddr_in addr4 = {
			.sin_family = AF_INET,
			.sin_port = htons(src),
			.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		};
		if (bind(s, (struct sockaddr *)&addr4, sizeof(addr4)))
			goto fail;
	}

	sp->sock = s;
	bitmap_set(udp_act[v6 ? V6 : V4][act], src);

	ev.data.u64 = ref.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, s, &ev);
	return s;

fail:
	close(s);
	return -1;
}

/**
 * struct udp_splice_new_ns_arg - Arguments for udp_splice_new_ns()
 * @c:		Execution context
 * @v6:		Set for IPv6
 * @src:	Source port of originating datagram, host order
 * @dst:	Destination port of originating datagram, host order
 * @s:		Newly created socket or negative error code
 */
struct udp_splice_new_ns_arg {
	const struct ctx *c;
	int v6;
	in_port_t src;
	int s;
};

/**
 * udp_splice_new_ns() - Enter namespace and call udp_splice_new()
 * @arg:	See struct udp_splice_new_ns_arg
 *
 * Return: 0
 */
static int udp_splice_new_ns(void *arg)
{
	struct udp_splice_new_ns_arg *a;

	a = (struct udp_splice_new_ns_arg *)arg;

	if (ns_enter(a->c))
		return 0;

	a->s = udp_splice_new(a->c, a->v6, a->src, true);

	return 0;
}

/**
 * sa_port() - Determine port from a sockaddr_in or sockaddr_in6
 * @v6:		Is @sa a sockaddr_in6 (otherwise sockaddr_in)?
 * @sa:		Pointer to either sockaddr_in or sockaddr_in6
 */
static in_port_t sa_port(bool v6, const void *sa)
{
	const struct sockaddr_in6 *sa6 = sa;
	const struct sockaddr_in *sa4 = sa;

	return v6 ? ntohs(sa6->sin6_port) : ntohs(sa4->sin_port);
}

/**
 * udp_splice_sendfrom() - Send datagrams from given port to given port
 * @c:		Execution context
 * @start:	Index of first datagram in udp[46]_l2_buf
 * @n:		Number of datagrams to send
 * @src:	Datagrams will be sent from this port (on origin side)
 * @dst:	Datagrams will be send to this port (on destination side)
 * @v6:		Send as IPv6?
 * @from_ns:	If true send from pasta ns to init, otherwise reverse
 * @allow_new:	If true create sending socket if needed, if false discard
 *              if no sending socket is available
 * @now:	Timestamp
 */
static void udp_splice_sendfrom(const struct ctx *c, unsigned start, unsigned n,
				in_port_t src, in_port_t dst,
				bool v6, bool from_ns, bool allow_new,
				const struct timespec *now)
{
	struct mmsghdr *mmh_recv, *mmh_send;
	unsigned int i;
	int s;

	if (v6) {
		mmh_recv = udp6_l2_mh_sock;
		mmh_send = udp6_mh_splice;
	} else {
		mmh_recv = udp4_l2_mh_sock;
		mmh_send = udp4_mh_splice;
	}

	if (from_ns) {
		src += c->udp.fwd_in.rdelta[src];
		s = udp_splice_init[v6][src].sock;
		if (!s && allow_new)
			s = udp_splice_new(c, v6, src, false);

		if (s < 0)
			return;

		udp_splice_ns[v6][dst].ts = now->tv_sec;
		udp_splice_init[v6][src].ts = now->tv_sec;
	} else {
		src += c->udp.fwd_out.rdelta[src];
		s = udp_splice_ns[v6][src].sock;
		if (!s && allow_new) {
			struct udp_splice_new_ns_arg arg = {
				c, v6, src, -1,
			};

			NS_CALL(udp_splice_new_ns, &arg);
			s = arg.s;
		}
		if (s < 0)
			return;

		udp_splice_init[v6][dst].ts = now->tv_sec;
		udp_splice_ns[v6][src].ts = now->tv_sec;
	}

	for (i = start; i < start + n; i++)
		mmh_send[i].msg_hdr.msg_iov->iov_len = mmh_recv[i].msg_len;

	sendmmsg(s, mmh_send + start, n, MSG_NOSIGNAL);
}

/**
 * udp_sock_handler_splice() - Handler for socket mapped to "spliced" connection
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
static void udp_sock_handler_splice(const struct ctx *c, union epoll_ref ref,
				    uint32_t events, const struct timespec *now)
{
	in_port_t dst = ref.r.p.udp.udp.port;
	int v6 = ref.r.p.udp.udp.v6, n, i, m;
	struct mmsghdr *mmh_recv;

	if (!(events & EPOLLIN))
		return;

	if (v6)
		mmh_recv = udp6_l2_mh_sock;
	else
		mmh_recv = udp4_l2_mh_sock;

	n = recvmmsg(ref.r.s, mmh_recv, UDP_MAX_FRAMES, 0, NULL);

	if (n <= 0)
		return;

	if (v6) {
		*((struct sockaddr_in6 *)&udp_splice_namebuf) =
		 ((struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
			.sin6_port = htons(dst),
			.sin6_scope_id = 0,
		});
	} else {
		*((struct sockaddr_in *)&udp_splice_namebuf) =
		 ((struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
			.sin_port = htons(dst),
			.sin_zero = { 0 },
		});
	}

	for (i = 0; i < n; i += m) {
		in_port_t src = sa_port(v6, mmh_recv[i].msg_hdr.msg_name);

		for (m = 1; i + m < n; m++) {
			void *mname = mmh_recv[i + m].msg_hdr.msg_name;
			if (sa_port(v6, mname) != src)
				break;
		}

		udp_splice_sendfrom(c, i, m, src, dst, v6, ref.r.p.udp.udp.ns,
				    ref.r.p.udp.udp.orig, now);
	}
}

/**
 * udp_update_hdr4() - Update headers for one IPv4 datagram
 * @c:		Execution context
 * @n:		Index of buffer in udp4_l2_buf pool
 * @dstport:	Destination port number
 * @now:	Current timestamp
 *
 * Return: size of tap frame with headers
 */
static size_t udp_update_hdr4(const struct ctx *c, int n, in_port_t dstport,
			      const struct timespec *now)
{
	struct udp4_l2_buf_t *b = &udp4_l2_buf[n];
	size_t ip_len, buf_len;
	in_port_t src_port;

	ip_len = udp4_l2_mh_sock[n].msg_len + sizeof(b->iph) + sizeof(b->uh);

	b->iph.tot_len = htons(ip_len);

	src_port = ntohs(b->s_in.sin_port);

	if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_match) &&
	    IN4_ARE_ADDR_EQUAL(&b->s_in.sin_addr, &c->ip4.dns_host) &&
	    src_port == 53) {
		b->iph.saddr = c->ip4.dns_match.s_addr;
	} else if (IN4_IS_ADDR_LOOPBACK(&b->s_in.sin_addr) ||
		   IN4_IS_ADDR_UNSPECIFIED(&b->s_in.sin_addr)||
		   IN4_ARE_ADDR_EQUAL(&b->s_in.sin_addr, &c->ip4.addr_seen)) {
		b->iph.saddr = c->ip4.gw.s_addr;
		udp_tap_map[V4][src_port].ts = now->tv_sec;
		udp_tap_map[V4][src_port].flags |= PORT_LOCAL;

		if (IN4_ARE_ADDR_EQUAL(&b->s_in.sin_addr.s_addr, &c->ip4.addr_seen))
			udp_tap_map[V4][src_port].flags &= ~PORT_LOOPBACK;
		else
			udp_tap_map[V4][src_port].flags |= PORT_LOOPBACK;

		bitmap_set(udp_act[V4][UDP_ACT_TAP], src_port);
	} else {
		b->iph.saddr = b->s_in.sin_addr.s_addr;
	}

	udp_update_check4(b);
	b->uh.source = b->s_in.sin_port;
	b->uh.dest = htons(dstport);
	b->uh.len = htons(udp4_l2_mh_sock[n].msg_len + sizeof(b->uh));

	buf_len = ip_len + sizeof(b->eh);

	if (c->mode == MODE_PASST) {
		b->vnet_len = htonl(buf_len);
		buf_len += sizeof(b->vnet_len);
	}

	return buf_len;
}

/**
 * udp_update_hdr6() - Update headers for one IPv6 datagram
 * @c:		Execution context
 * @n:		Index of buffer in udp6_l2_buf pool
 * @dstport:	Destination port number
 * @now:	Current timestamp
 *
 * Return: size of tap frame with headers
 */
static size_t udp_update_hdr6(const struct ctx *c, int n, in_port_t dstport,
			      const struct timespec *now)
{
	struct udp6_l2_buf_t *b = &udp6_l2_buf[n];
	size_t ip_len, buf_len;
	struct in6_addr *src;
	in_port_t src_port;

	src = &b->s_in6.sin6_addr;
	src_port = ntohs(b->s_in6.sin6_port);

	ip_len = udp6_l2_mh_sock[n].msg_len + sizeof(b->ip6h) + sizeof(b->uh);

	b->ip6h.payload_len = htons(udp6_l2_mh_sock[n].msg_len + sizeof(b->uh));

	if (IN6_IS_ADDR_LINKLOCAL(src)) {
		b->ip6h.daddr = c->ip6.addr_ll_seen;
		b->ip6h.saddr = b->s_in6.sin6_addr;
	} else if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_match) &&
		   IN6_ARE_ADDR_EQUAL(src, &c->ip6.dns_host) &&
		   src_port == 53) {
		b->ip6h.daddr = c->ip6.addr_seen;
		b->ip6h.saddr = c->ip6.dns_match;
	} else if (IN6_IS_ADDR_LOOPBACK(src)			||
		   IN6_ARE_ADDR_EQUAL(src, &c->ip6.addr_seen)	||
		   IN6_ARE_ADDR_EQUAL(src, &c->ip6.addr)) {
		b->ip6h.daddr = c->ip6.addr_ll_seen;

		if (IN6_IS_ADDR_LINKLOCAL(&c->ip6.gw))
			b->ip6h.saddr = c->ip6.gw;
		else
			b->ip6h.saddr = c->ip6.addr_ll;

		udp_tap_map[V6][src_port].ts = now->tv_sec;
		udp_tap_map[V6][src_port].flags |= PORT_LOCAL;

		if (IN6_IS_ADDR_LOOPBACK(src))
			udp_tap_map[V6][src_port].flags |= PORT_LOOPBACK;
		else
			udp_tap_map[V6][src_port].flags &= ~PORT_LOOPBACK;

		if (IN6_ARE_ADDR_EQUAL(src, &c->ip6.addr))
			udp_tap_map[V6][src_port].flags |= PORT_GUA;
		else
			udp_tap_map[V6][src_port].flags &= ~PORT_GUA;

		bitmap_set(udp_act[V6][UDP_ACT_TAP], src_port);
	} else {
		b->ip6h.daddr = c->ip6.addr_seen;
		b->ip6h.saddr = b->s_in6.sin6_addr;
	}

	b->uh.source = b->s_in6.sin6_port;
	b->uh.dest = htons(dstport);
	b->uh.len = b->ip6h.payload_len;

	b->ip6h.hop_limit = IPPROTO_UDP;
	b->ip6h.version = b->ip6h.nexthdr = b->uh.check = 0;
	b->uh.check = csum(&b->ip6h, ip_len, 0);
	b->ip6h.version = 6;
	b->ip6h.nexthdr = IPPROTO_UDP;
	b->ip6h.hop_limit = 255;

	buf_len = ip_len + sizeof(b->eh);

	if (c->mode == MODE_PASST) {
		b->vnet_len = htonl(buf_len);
		buf_len += sizeof(b->vnet_len);
	}

	return buf_len;
}

/**
 * udp_tap_send_pasta() - Send datagrams to the pasta tap interface
 * @c:		Execution context
 * @mmh:	Array of message headers to send
 * @n:		Number of message headers to send
 *
 * #syscalls:pasta write
 */
static void udp_tap_send_pasta(const struct ctx *c, struct mmsghdr *mmh,
			       unsigned int n)
{
	unsigned int i, j;

	for (i = 0; i < n; i++) {
		for (j = 0; j < mmh[i].msg_hdr.msg_iovlen; j++) {
			struct iovec *iov = &mmh[i].msg_hdr.msg_iov[j];

			/* We can't use writev() because the tap
			 * character device relies on the write()
			 * boundaries to discern frame boundaries
			 */
			if (write(c->fd_tap, iov->iov_base, iov->iov_len) < 0)
				debug("tap write: %s", strerror(errno));
			else
				pcap(iov->iov_base, iov->iov_len);
		}
	}
}

/**
 * udp_tap_send_passt() - Send datagrams to the passt tap interface
 * @c:		Execution context
 * @mmh:	Array of message headers to send
 * @n:		Number of message headers to send
 *
 * #syscalls:passt sendmmsg sendmsg
 */
static void udp_tap_send_passt(const struct ctx *c, struct mmsghdr *mmh, int n)
{
	struct msghdr *last_mh;
	ssize_t missing = 0;
	size_t msg_len = 0;
	unsigned int i;
	int ret;

	ret = sendmmsg(c->fd_tap, mmh, n, MSG_NOSIGNAL | MSG_DONTWAIT);
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
	last_mh = &mmh[ret - 1].msg_hdr;
	for (i = 0; i < last_mh->msg_iovlen; i++) {
		if (missing <= 0) {
			msg_len += last_mh->msg_iov[i].iov_len;
			missing = msg_len - mmh[ret - 1].msg_len;
		}

		if (missing > 0) {
			uint8_t **iov_base;
			int first_offset;

			iov_base = (uint8_t **)&last_mh->msg_iov[i].iov_base;
			first_offset = last_mh->msg_iov[i].iov_len - missing;
			*iov_base += first_offset;
			last_mh->msg_iov[i].iov_len = missing;

			last_mh->msg_iov = &last_mh->msg_iov[i];

			if (sendmsg(c->fd_tap, last_mh, MSG_NOSIGNAL) < 0)
				debug("UDP: %li bytes to tap missing", missing);

			*iov_base -= first_offset;
			break;
		}
	}

	pcapmm(mmh, ret);
}

/**
 * udp_tap_send() - Prepare UDP datagrams and send to tap interface
 * @c:		Execution context
 * @start:	Index of first datagram in udp[46]_l2_buf pool
 * @n:		Number of datagrams to send
 * @dstport:	Destination port number
 * @v6:		True if using IPv6
 * @now:	Current timestamp
 *
 * Return: size of tap frame with headers
 */
static void udp_tap_send(const struct ctx *c,
			 unsigned int start, unsigned int n,
			 in_port_t dstport, bool v6, const struct timespec *now)
{
	int msg_bufs = 0, msg_i = 0;
	struct mmsghdr *tap_mmh;
	struct iovec *tap_iov;
	ssize_t msg_len = 0;
	unsigned int i;

	if (v6) {
		tap_mmh = udp6_l2_mh_tap;
		tap_iov = udp6_l2_iov_tap;
	} else {
		tap_mmh = udp4_l2_mh_tap;
		tap_iov = udp4_l2_iov_tap;
	}

	tap_mmh[0].msg_hdr.msg_iov = &tap_iov[start];
	for (i = start; i < start + n; i++) {
		size_t buf_len;

		if (v6)
			buf_len = udp_update_hdr6(c, i, dstport, now);
		else
			buf_len = udp_update_hdr4(c, i, dstport, now);

		tap_iov[i].iov_len = buf_len;

		/* With bigger messages, qemu closes the connection. */
		if (c->mode == MODE_PASST && msg_bufs &&
		    msg_len + buf_len > SHRT_MAX) {
			tap_mmh[msg_i].msg_hdr.msg_iovlen = msg_bufs;
			msg_i++;
			tap_mmh[msg_i].msg_hdr.msg_iov = &tap_iov[i];
			msg_len = msg_bufs = 0;
		}
		msg_len += buf_len;
		msg_bufs++;
	}
	tap_mmh[msg_i].msg_hdr.msg_iovlen = msg_bufs;

	if (c->mode == MODE_PASTA)
		udp_tap_send_pasta(c, tap_mmh, msg_i + 1);
	else
		udp_tap_send_passt(c, tap_mmh, msg_i + 1);
}

/**
 * udp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 *
 * #syscalls recvmmsg
 */
void udp_sock_handler(const struct ctx *c, union epoll_ref ref, uint32_t events,
		      const struct timespec *now)
{
	in_port_t dstport = ref.r.p.udp.udp.port;
	bool v6 = ref.r.p.udp.udp.v6;
	struct mmsghdr *sock_mmh;
	ssize_t n;

	if (events == EPOLLERR)
		return;

	if (ref.r.p.udp.udp.splice) {
		udp_sock_handler_splice(c, ref, events, now);
		return;
	}

	if (ref.r.p.udp.udp.v6)
		sock_mmh = udp6_l2_mh_sock;
	else
		sock_mmh = udp4_l2_mh_sock;

	n = recvmmsg(ref.r.s, sock_mmh, UDP_TAP_FRAMES, 0, NULL);
	if (n <= 0)
		return;

	udp_tap_send(c, 0, n, dstport, v6, now);
}

/**
 * udp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Destination address
 * @p:		Pool of UDP packets, with UDP headers
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 *
 * #syscalls sendmmsg
 */
int udp_tap_handler(struct ctx *c, int af, const void *addr,
		    const struct pool *p, const struct timespec *now)
{
	struct mmsghdr mm[UIO_MAXIOV];
	struct iovec m[UIO_MAXIOV];
	struct sockaddr_in6 s_in6;
	struct sockaddr_in s_in;
	struct sockaddr *sa;
	int i, s, count = 0;
	in_port_t src, dst;
	struct udphdr *uh;
	socklen_t sl;

	(void)c;

	uh = packet_get(p, 0, 0, sizeof(*uh), NULL);
	if (!uh)
		return 1;

	/* The caller already checks that all the messages have the same source
	 * and destination, so we can just take those from the first message.
	 */
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
			union udp_epoll_ref uref = { .udp.port = src };

			s = sock_l4(c, AF_INET, IPPROTO_UDP, NULL, NULL, src,
				    uref.u32);
			if (s < 0)
				return p->count;

			udp_tap_map[V4][src].sock = s;
			bitmap_set(udp_act[V4][UDP_ACT_TAP], src);
		}

		udp_tap_map[V4][src].ts = now->tv_sec;

		if (IN4_ARE_ADDR_EQUAL(&s_in.sin_addr, &c->ip4.gw) &&
		    !c->no_map_gw) {
			if (!(udp_tap_map[V4][dst].flags & PORT_LOCAL) ||
			    (udp_tap_map[V4][dst].flags & PORT_LOOPBACK))
				s_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			else
				s_in.sin_addr = c->ip4.addr_seen;
		} else if (IN4_ARE_ADDR_EQUAL(&s_in.sin_addr,
					      &c->ip4.dns_match) &&
			   ntohs(s_in.sin_port) == 53) {
			s_in.sin_addr = c->ip4.dns[0];
		}
	} else {
		s_in6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = uh->dest,
			.sin6_addr = *(struct in6_addr *)addr,
		};
		const void *bind_addr = &in6addr_any;

		sa = (struct sockaddr *)&s_in6;
		sl = sizeof(s_in6);

		if (IN6_ARE_ADDR_EQUAL(addr, &c->ip6.gw) && !c->no_map_gw) {
			if (!(udp_tap_map[V6][dst].flags & PORT_LOCAL) ||
			    (udp_tap_map[V6][dst].flags & PORT_LOOPBACK))
				s_in6.sin6_addr = in6addr_loopback;
			else if (udp_tap_map[V6][dst].flags & PORT_GUA)
				s_in6.sin6_addr = c->ip6.addr;
			else
				s_in6.sin6_addr = c->ip6.addr_seen;
		} else if (IN6_ARE_ADDR_EQUAL(addr, &c->ip6.dns_match) &&
			   ntohs(s_in6.sin6_port) == 53) {
			s_in6.sin6_addr = c->ip6.dns[0];
		} else if (IN6_IS_ADDR_LINKLOCAL(&s_in6.sin6_addr)) {
			bind_addr = &c->ip6.addr_ll;
		}

		if (!(s = udp_tap_map[V6][src].sock)) {
			union udp_epoll_ref uref = { .udp.v6 = 1,
						     .udp.port = src };

			s = sock_l4(c, AF_INET6, IPPROTO_UDP, bind_addr, NULL,
				    src, uref.u32);
			if (s < 0)
				return p->count;

			udp_tap_map[V6][src].sock = s;
			bitmap_set(udp_act[V6][UDP_ACT_TAP], src);
		}

		udp_tap_map[V6][src].ts = now->tv_sec;
	}

	for (i = 0; i < (int)p->count; i++) {
		struct udphdr *uh_send;
		size_t len;

		uh_send = packet_get(p, i, 0, sizeof(*uh), &len);
		if (!uh_send)
			return p->count;

		mm[i].msg_hdr.msg_name = sa;
		mm[i].msg_hdr.msg_namelen = sl;

		if (len) {
			m[i].iov_base = (char *)(uh_send + 1);
			m[i].iov_len = len;

			mm[i].msg_hdr.msg_iov = m + i;
			mm[i].msg_hdr.msg_iovlen = 1;
		} else {
			mm[i].msg_hdr.msg_iov = NULL;
			mm[i].msg_hdr.msg_iovlen = 0;
		}

		mm[i].msg_hdr.msg_control = NULL;
		mm[i].msg_hdr.msg_controllen = 0;
		mm[i].msg_hdr.msg_flags = 0;

		count++;
	}

	count = sendmmsg(s, mm, count, MSG_NOSIGNAL);
	if (count < 0)
		return 1;

	return count;
}

/**
 * udp_sock_init() - Initialise listening sockets for a given port
 * @c:		Execution context
 * @ns:		In pasta mode, if set, bind with loopback address in namespace
 * @af:		Address family to select a specific IP version, or AF_UNSPEC
 * @addr:	Pointer to address for binding, NULL if not configured
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 */
void udp_sock_init(const struct ctx *c, int ns, sa_family_t af,
		   const void *addr, const char *ifname, in_port_t port)
{
	union udp_epoll_ref uref = { .u32 = 0 };
	const void *bind_addr;
	int s;

	if (ns) {
		uref.udp.port = (in_port_t)(port +
					    c->udp.fwd_out.f.delta[port]);
	} else {
		uref.udp.port = (in_port_t)(port +
					    c->udp.fwd_in.f.delta[port]);
	}

	if ((af == AF_INET || af == AF_UNSPEC) && c->ifi4) {
		if (!addr && c->mode == MODE_PASTA)
			bind_addr = &c->ip4.addr;
		else
			bind_addr = addr;

		uref.udp.v6 = 0;

		if (!ns) {
			uref.udp.splice = 0;
			s = sock_l4(c, AF_INET, IPPROTO_UDP, bind_addr, ifname,
				    port, uref.u32);

			udp_tap_map[V4][uref.udp.port].sock = s;

			if (c->mode == MODE_PASTA) {
				bind_addr = &(uint32_t){ htonl(INADDR_LOOPBACK) };
				uref.udp.splice = uref.udp.orig = true;

				s = sock_l4(c, AF_INET, IPPROTO_UDP, bind_addr,
					    ifname, port, uref.u32);
				udp_splice_init[V4][port].sock = s;
			}
		} else {
			uref.udp.splice = uref.udp.orig = uref.udp.ns = true;

			bind_addr = &(uint32_t){ htonl(INADDR_LOOPBACK) };

			s = sock_l4(c, AF_INET, IPPROTO_UDP, bind_addr,
				    ifname, port, uref.u32);
			udp_splice_ns[V4][port].sock = s;
		}
	}

	if ((af == AF_INET6 || af == AF_UNSPEC) && c->ifi6) {
		if (!addr && c->mode == MODE_PASTA)
			bind_addr = &c->ip6.addr;
		else
			bind_addr = addr;

		uref.udp.v6 = 1;

		if (!ns) {
			uref.udp.splice = 0;
			s = sock_l4(c, AF_INET6, IPPROTO_UDP, bind_addr, ifname,
				    port, uref.u32);

			udp_tap_map[V6][uref.udp.port].sock = s;

			if (c->mode == MODE_PASTA) {
				bind_addr = &in6addr_loopback;
				uref.udp.splice = uref.udp.orig = true;

				s = sock_l4(c, AF_INET6, IPPROTO_UDP, bind_addr,
					    ifname, port, uref.u32);
				udp_splice_init[V6][port].sock = s;
			}
		} else {
			bind_addr = &in6addr_loopback;
			uref.udp.splice = uref.udp.orig = uref.udp.ns = true;

			s = sock_l4(c, AF_INET6, IPPROTO_UDP, bind_addr,
				    ifname, port, uref.u32);
			udp_splice_ns[V6][port].sock = s;
		}
	}
}

/**
 * udp_sock_init_ns() - Bind sockets in namespace for inbound connections
 * @arg:	Execution context
 *
 * Return: 0
 */
int udp_sock_init_ns(void *arg)
{
	struct ctx *c = (struct ctx *)arg;
	unsigned dst;

	if (ns_enter(c))
		return 0;

	for (dst = 0; dst < NUM_PORTS; dst++) {
		if (!bitmap_isset(c->udp.fwd_out.f.map, dst))
			continue;

		udp_sock_init(c, 1, AF_UNSPEC, NULL, NULL, dst);
	}

	return 0;
}

/**
 * udp_splice_iov_init() - Set up buffers and descriptors for recvmmsg/sendmmsg
 */
static void udp_splice_iov_init(void)
{
	int i;

	for (i = 0; i < UDP_MAX_FRAMES; i++) {
		struct msghdr *mh4 = &udp4_mh_splice[i].msg_hdr;
		struct msghdr *mh6 = &udp6_mh_splice[i].msg_hdr;

		mh4->msg_name = mh6->msg_name = &udp_splice_namebuf;
		mh4->msg_namelen = sizeof(udp_splice_namebuf);
		mh6->msg_namelen = sizeof(udp_splice_namebuf);

		udp4_iov_splice[i].iov_base = udp4_l2_buf[i].data;
		udp6_iov_splice[i].iov_base = udp6_l2_buf[i].data;

		mh4->msg_iov = &udp4_iov_splice[i];
		mh6->msg_iov = &udp6_iov_splice[i];
		mh4->msg_iovlen = mh6->msg_iovlen = 1;
	}
}

/**
 * udp_init() - Initialise per-socket data, and sockets in namespace
 * @c:		Execution context
 *
 * Return: 0
 */
int udp_init(struct ctx *c)
{
	if (c->ifi4)
		udp_sock4_iov_init(c);

	if (c->ifi6)
		udp_sock6_iov_init(c);

	udp_invert_portmap(&c->udp.fwd_in);
	udp_invert_portmap(&c->udp.fwd_out);

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
			  in_port_t port, const struct timespec *ts)
{
	struct udp_splice_port *sp;
	struct udp_tap_port *tp;
	int s = -1;

	switch (type) {
	case UDP_ACT_TAP:
		tp = &udp_tap_map[v6 ? V6 : V4][port];

		if (ts->tv_sec - tp->ts > UDP_CONN_TIMEOUT) {
			s = tp->sock;
			tp->flags = 0;
		}

		break;
	case UDP_ACT_SPLICE_INIT:
		sp = &udp_splice_init[v6 ? V6 : V4][port];

		if (ts->tv_sec - sp->ts > UDP_CONN_TIMEOUT)
			s = sp->sock;

		break;
	case UDP_ACT_SPLICE_NS:
		sp = &udp_splice_ns[v6 ? V6 : V4][port];

		if (ts->tv_sec - sp->ts > UDP_CONN_TIMEOUT)
			s = sp->sock;

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
void udp_timer(struct ctx *c, const struct timespec *ts)
{
	int n, t, v6 = 0;
	unsigned int i;
	long *word, tmp;

	if (!c->ifi4)
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

	if (!v6 && c->ifi6) {
		v6 = 1;
		goto v6;
	}
}

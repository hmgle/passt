// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp.c - TCP L2-L4 translation state machine
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 *
 * PASST mode
 * ==========
 *
 * This implementation maps TCP traffic between a single L2 interface (tap) and
 * native TCP (L4) sockets, mimicking and reproducing as closely as possible the
 * inferred behaviour of applications running on a guest, connected via said L2
 * interface. Four connection flows are supported:
 * - from the local host to the guest behind the tap interface:
 *   - this is the main use case for proxies in service meshes
 *   - we bind to configured local ports, and relay traffic between L4 sockets
 *     with local endpoints and the L2 interface
 * - from remote hosts to the guest behind the tap interface:
 *   - this might be needed for services that need to be addressed directly,
 *     and typically configured with special port forwarding rules (which are
 *     not needed here)
 *   - we also relay traffic between L4 sockets with remote endpoints and the L2
 *     interface
 * - from the guest to the local host:
 *   - this is not observed in practice, but implemented for completeness and
 *     transparency
 * - from the guest to external hosts:
 *   - this might be needed for applications running on the guest that need to
 *     directly access internet services (e.g. NTP)
 *
 * Relevant goals are:
 * - transparency: sockets need to behave as if guest applications were running
 *   directly on the host. This is achieved by:
 *   - avoiding port and address translations whenever possible
 *   - mirroring TCP dynamics by observation of socket parameters (TCP_INFO
 *     socket option) and TCP headers of packets coming from the tap interface,
 *     reapplying those parameters in both flow directions (including TCP_MSS,
 *     TCP_WINDOW_CLAMP socket options)
 * - simplicity: only a small subset of TCP logic is implemented here and
 *   delegated as much as possible to the TCP implementations of guest and host
 *   kernel. This is achieved by:
 *   - avoiding a complete TCP stack reimplementation, with a modified TCP state
 *     machine focused on the translation of observed events instead
 *   - mirroring TCP dynamics as described above and hence avoiding the need for
 *     segmentation, explicit queueing, and reassembly of segments
 * - security:
 *   - no dynamic memory allocation is performed
 *   - TODO: synflood protection
 *
 * Portability is limited by usage of Linux-specific socket options.
 *
 *
 * Limits
 * ------
 *
 * To avoid the need for dynamic memory allocation, a maximum, reasonable amount
 * of connections is defined by TCP_MAX_CONNS (currently 128k).
 *
 * Data needs to linger on sockets as long as it's not acknowledged by the
 * guest, and is read using MSG_PEEK into preallocated static buffers sized
 * to the maximum supported window, 16 MiB ("discard" buffer, for already-sent
 * data) plus a number of maximum-MSS-sized buffers. This imposes a practical
 * limitation on window scaling, that is, the maximum factor is 256. Larger
 * factors will be accepted, but resulting, larger values are never advertised
 * to the other side, and not used while queueing data.
 *
 *
 * Ports
 * -----
 *
 * To avoid the need for ad-hoc configuration of port forwarding or allowed
 * ports, listening sockets can be opened and bound to all unbound ports on the
 * host, as far as process capabilities allow. This service needs to be started
 * after any application proxy that needs to bind to local ports. Mapped ports
 * can also be configured explicitly.
 *
 * No port translation is needed for connections initiated remotely or by the
 * local host: source port from socket is reused while establishing connections
 * to the guest.
 *
 * For connections initiated by the guest, it's not possible to force the same
 * source port as connections are established by the host kernel: that's the
 * only port translation needed.
 *
 *
 * Connection tracking and storage
 * -------------------------------
 *
 * Connections are tracked by struct tcp_tap_conn entries in the @tc
 * array, containing addresses, ports, TCP states and parameters. This
 * is statically allocated and indexed by an arbitrary connection
 * number. The array is compacted whenever a connection is closed, by
 * remapping the highest connection index in use to the one freed up.
 *
 * References used for the epoll interface report the connection index used for
 * the @tc array.
 *
 * IPv4 addresses are stored as IPv4-mapped IPv6 addresses to avoid the need for
 * separate data structures depending on the protocol version.
 *
 * - Inbound connection requests (to the guest) are mapped using the triple
 *   < source IP address, source port, destination port >
 * - Outbound connection requests (from the guest) are mapped using the triple
 *   < destination IP address, destination port, source port >
 *   where the source port is the one used by the guest, not the one used by the
 *   corresponding host socket
 *
 *
 * Initialisation
 * --------------
 *
 * Up to 2^15 + 2^14 listening sockets (excluding ephemeral ports, repeated for
 * IPv4 and IPv6) can be opened and bound to wildcard addresses. Some will fail
 * to bind (for low ports, or ports already bound, e.g. by a proxy). These are
 * added to the epoll list, with no separate storage.
 *
 *
 * Events and states
 * -----------------
 *
 * Instead of tracking connection states using a state machine, connection
 * events are used to determine state and actions for a given connection. This
 * makes the implementation simpler as most of the relevant tasks deal with
 * reactions to events, rather than state-associated actions. For user
 * convenience, approximate states are mapped in logs from events by
 * @tcp_state_str.
 *
 * The events are:
 *
 * - SOCK_ACCEPTED	connection accepted from socket, SYN sent to tap/guest
 *
 * - TAP_SYN_RCVD	tap/guest initiated connection, SYN received
 *
 * - TAP_SYN_ACK_SENT	SYN, ACK sent to tap/guest, valid for TAP_SYN_RCVD only
 *
 * - ESTABLISHED	connection established, the following events are valid:
 *
 * - SOCK_FIN_RCVD	FIN (EPOLLRDHUP) received from socket
 *
 * - SOCK_FIN_SENT	FIN (write shutdown) sent to socket
 *
 * - TAP_FIN_RCVD	FIN received from tap/guest
 *
 * - TAP_FIN_SENT	FIN sent to tap/guest
 *
 * - TAP_FIN_ACKED	ACK to FIN seen from tap/guest
 *
 * Setting any event in CONN_STATE_BITS (SOCK_ACCEPTED, TAP_SYN_RCVD,
 * ESTABLISHED) clears all the other events, as those represent the fundamental
 * connection states. No events (events == CLOSED) means the connection is
 * closed.
 *
 * Connection setup
 * ----------------
 *
 * - inbound connection (from socket to guest): on accept() from listening
 *   socket, the new socket is mapped in connection tracking table, and
 *   three-way handshake initiated towards the guest, advertising MSS and window
 *   size and scaling from socket parameters
 * - outbound connection (from guest to socket): on SYN segment from guest, a
 *   new socket is created and mapped in connection tracking table, setting
 *   MSS and window clamping from header and option of the observed SYN segment
 *
 *
 * Aging and timeout
 * -----------------
 *
 * Timeouts are implemented by means of timerfd timers, set based on flags:
 *
 * - SYN_TIMEOUT: if no ACK is received from tap/guest during handshake (flag
 *   ACK_FROM_TAP_DUE without ESTABLISHED event) within this time, reset the
 *   connection
 *
 * - ACK_TIMEOUT: if no ACK segment was received from tap/guest, after sending
 *   data (flag ACK_FROM_TAP_DUE with ESTABLISHED event), re-send data from the
 *   socket and reset sequence to what was acknowledged. If this persists for
 *   more than TCP_MAX_RETRANS times in a row, reset the connection
 *
 * - FIN_TIMEOUT: if a FIN segment was sent to tap/guest (flag ACK_FROM_TAP_DUE
 *   with TAP_FIN_SENT event), and no ACK is received within this time, reset
 *   the connection
 *
 * - FIN_TIMEOUT: if a FIN segment was acknowledged by tap/guest and a FIN
 *   segment (write shutdown) was sent via socket (events SOCK_FIN_SENT and
 *   TAP_FIN_ACKED), but no socket activity is detected from the socket within
 *   this time, reset the connection
 *
 * - ACT_TIMEOUT, in the presence of any event: if no activity is detected on
 *   either side, the connection is reset
 *
 * - ACK_INTERVAL elapsed after data segment received from tap without having
 *   sent an ACK segment, or zero-sized window advertised to tap/guest (flag
 *   ACK_TO_TAP_DUE): forcibly check if an ACK segment can be sent
 *
 *
 * Summary of data flows (with ESTABLISHED event)
 * ----------------------------------------------
 *
 * @seq_to_tap:		next sequence for packets to tap/guest
 * @seq_ack_from_tap:	last ACK number received from tap/guest
 * @seq_from_tap:	next sequence for packets from tap/guest (expected)
 * @seq_ack_to_tap:	last ACK number sent to tap/guest
 *
 * @seq_init_from_tap:	initial sequence number from tap/guest
 * @seq_init_to_tap:	initial sequence number from tap/guest
 *
 * @wnd_from_tap:	last window size received from tap, never scaled
 * @wnd_from_tap:	last window size advertised from tap, never scaled
 *
 * - from socket to tap/guest:
 *   - on new data from socket:
 *     - peek into buffer
 *     - send data to tap/guest:
 *       - starting at offset (@seq_to_tap - @seq_ack_from_tap)
 *       - in MSS-sized segments
 *       - increasing @seq_to_tap at each segment
 *       - up to window (until @seq_to_tap - @seq_ack_from_tap <= @wnd_from_tap)
 *     - on read error, send RST to tap/guest, close socket
 *     - on zero read, send FIN to tap/guest, set TAP_FIN_SENT
 *   - on ACK from tap/guest:
 *     - set @ts_ack_from_tap
 *     - check if it's the second duplicated ACK
 *     - consume buffer by difference between new ack_seq and @seq_ack_from_tap
 *     - update @seq_ack_from_tap from ack_seq in header
 *     - on two duplicated ACKs, reset @seq_to_tap to @seq_ack_from_tap, and
 *       resend with steps listed above
 *     - set TCP_WINDOW_CLAMP from TCP header from tap
 *
 * - from tap/guest to socket:
 *   - on packet from tap/guest:
 *     - set @ts_tap_act
 *     - set TCP_WINDOW_CLAMP from TCP header from tap
 *     - check seq from header against @seq_from_tap, if data is missing, send
 *       two ACKs with number @seq_ack_to_tap, discard packet
 *     - otherwise queue data to socket, set @seq_from_tap to seq from header
 *       plus payload length
 *     - in ESTABLISHED state, send ACK to tap as soon as we queue to the
 *       socket. In other states, query socket for TCP_INFO, set
 *       @seq_ack_to_tap to (tcpi_bytes_acked + @seq_init_from_tap) % 2^32 and
 *       send ACK to tap/guest
 *
 *
 * PASTA mode
 * ==========
 *
 * For traffic directed to TCP ports configured for mapping to the tuntap device
 * in the namespace, and for non-local traffic coming from the tuntap device,
 * the implementation is identical as the PASST mode described in the previous
 * section.
 *
 * For local traffic directed to TCP ports configured for direct mapping between
 * namespaces, see the implementation in tcp_splice.c.
 */

#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#ifdef HAS_GETRANDOM
#include <sys/random.h>
#endif
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <linux/tcp.h> /* For struct tcp_info */

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "tap.h"
#include "siphash.h"
#include "pcap.h"
#include "conf.h"
#include "tcp_splice.h"
#include "log.h"
#include "inany.h"

#include "tcp_conn.h"

#define TCP_FRAMES_MEM			128
#define TCP_FRAMES							\
	(c->mode == MODE_PASST ? TCP_FRAMES_MEM : 1)

#define TCP_FILE_PRESSURE		30	/* % of c->nofile */
#define TCP_CONN_PRESSURE		30	/* % of c->tcp.conn_count */

#define TCP_HASH_TABLE_LOAD		70		/* % */
#define TCP_HASH_TABLE_SIZE		(TCP_MAX_CONNS * 100 /		\
					 TCP_HASH_TABLE_LOAD)

#define MAX_WS				8
#define MAX_WINDOW			(1 << (16 + (MAX_WS)))

/* MSS rounding: see SET_MSS() */
#define MSS_DEFAULT			536

struct tcp4_l2_head {	/* For MSS4 macro: keep in sync with tcp4_l2_buf_t */
	uint32_t psum;
	uint32_t tsum;
#ifdef __AVX2__
	uint8_t pad[18];
#else
	uint8_t pad[2];
#endif
	struct tap_hdr taph;
	struct iphdr iph;
	struct tcphdr th;
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)));
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))));
#endif

struct tcp6_l2_head {	/* For MSS6 macro: keep in sync with tcp6_l2_buf_t */
#ifdef __AVX2__
	uint8_t pad[14];
#else
	uint8_t pad[2];
#endif
	struct tap_hdr taph;
	struct ipv6hdr ip6h;
	struct tcphdr th;
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)));
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))));
#endif

#define MSS4	ROUND_DOWN(USHRT_MAX - sizeof(struct tcp4_l2_head), 4)
#define MSS6	ROUND_DOWN(USHRT_MAX - sizeof(struct tcp6_l2_head), 4)

#define WINDOW_DEFAULT			14600		/* RFC 6928 */
#ifdef HAS_SND_WND
# define KERNEL_REPORTS_SND_WND(c)	(c->tcp.kernel_snd_wnd)
#else
# define KERNEL_REPORTS_SND_WND(c)	(0 && (c))
#endif

#define ACK_INTERVAL			10		/* ms */
#define SYN_TIMEOUT			10		/* s */
#define ACK_TIMEOUT			2
#define FIN_TIMEOUT			60
#define ACT_TIMEOUT			7200

#define LOW_RTT_TABLE_SIZE		8
#define LOW_RTT_THRESHOLD		10 /* us */

/* We need to include <linux/tcp.h> for tcpi_bytes_acked, instead of
 * <netinet/tcp.h>, but that doesn't include a definition for SOL_TCP
 */
#define SOL_TCP				IPPROTO_TCP

#define SEQ_LE(a, b)			((b) - (a) < MAX_WINDOW)
#define SEQ_LT(a, b)			((b) - (a) - 1 < MAX_WINDOW)
#define SEQ_GE(a, b)			((a) - (b) < MAX_WINDOW)
#define SEQ_GT(a, b)			((a) - (b) - 1 < MAX_WINDOW)

#define FIN		(1 << 0)
#define SYN		(1 << 1)
#define RST		(1 << 2)
#define ACK		(1 << 4)
/* Flags for internal usage */
#define DUP_ACK		(1 << 5)
#define ACK_IF_NEEDED	0		/* See tcp_send_flag() */

#define OPT_EOL		0
#define OPT_NOP		1
#define OPT_MSS		2
#define OPT_MSS_LEN	4
#define OPT_WS		3
#define OPT_WS_LEN	3
#define OPT_SACKP	4
#define OPT_SACK	5
#define OPT_TS		8

#define CONN_V4(conn)		(!!inany_v4(&(conn)->addr))
#define CONN_V6(conn)		(!CONN_V4(conn))
#define CONN_IS_CLOSING(conn)						\
	((conn->events & ESTABLISHED) &&				\
	 (conn->events & (SOCK_FIN_RCVD | TAP_FIN_RCVD)))
#define CONN_HAS(conn, set)	((conn->events & (set)) == (set))

static const char *tcp_event_str[] __attribute((__unused__)) = {
	"SOCK_ACCEPTED", "TAP_SYN_RCVD", "ESTABLISHED", "TAP_SYN_ACK_SENT",

	"SOCK_FIN_RCVD", "SOCK_FIN_SENT", "TAP_FIN_RCVD", "TAP_FIN_SENT",
	"TAP_FIN_ACKED",
};

static const char *tcp_state_str[] __attribute((__unused__)) = {
	"SYN_RCVD", "SYN_SENT", "ESTABLISHED",
	"SYN_RCVD",	/* approximately maps to TAP_SYN_ACK_SENT */

	/* Passive close: */
	"CLOSE_WAIT", "CLOSE_WAIT", "LAST_ACK", "LAST_ACK", "LAST_ACK",
	/* Active close (+5): */
	"CLOSING", "FIN_WAIT_1", "FIN_WAIT_1", "FIN_WAIT_2", "TIME_WAIT",
};

static const char *tcp_flag_str[] __attribute((__unused__)) = {
	"STALLED", "LOCAL", "WND_CLAMPED", "ACTIVE_CLOSE", "ACK_TO_TAP_DUE",
	"ACK_FROM_TAP_DUE",
};

/* Listening sockets, used for automatic port forwarding in pasta mode only */
static int tcp_sock_init_ext	[NUM_PORTS][IP_VERSIONS];
static int tcp_sock_ns		[NUM_PORTS][IP_VERSIONS];

/* Table of destinations with very low RTT (assumed to be local), LRU */
static union inany_addr low_rtt_dst[LOW_RTT_TABLE_SIZE];

/* Static buffers */

/**
 * tcp4_l2_buf_t - Pre-cooked IPv4 packet buffers for tap connections
 * @psum:	Partial IP header checksum (excluding tot_len and saddr)
 * @tsum:	Partial TCP header checksum (excluding length and saddr)
 * @pad:	Align TCP header to 32 bytes, for AVX2 checksum calculation only
 * @taph:	Tap-level headers (partially pre-filled)
 * @iph:	Pre-filled IP header (except for tot_len and saddr)
 * @uh:		Headroom for TCP header
 * @data:	Storage for TCP payload
 */
static struct tcp4_l2_buf_t {
	uint32_t psum;		/* 0 */
	uint32_t tsum;		/* 4 */
#ifdef __AVX2__
	uint8_t pad[18];	/* 8, align th to 32 bytes */
#else
	uint8_t pad[2];		/*	align iph to 4 bytes	8 */
#endif
	struct tap_hdr taph;	/* 26				10 */
	struct iphdr iph;	/* 44				28 */
	struct tcphdr th;	/* 64				48 */
	uint8_t data[MSS4];	/* 84				68 */
				/* 65536			65532 */
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
tcp4_l2_buf[TCP_FRAMES_MEM];

static unsigned int tcp4_l2_buf_used;

/**
 * tcp6_l2_buf_t - Pre-cooked IPv6 packet buffers for tap connections
 * @pad:	Align IPv6 header for checksum calculation to 32B (AVX2) or 4B
 * @taph:	Tap-level headers (partially pre-filled)
 * @ip6h:	Pre-filled IP header (except for payload_len and addresses)
 * @th:		Headroom for TCP header
 * @data:	Storage for TCP payload
 */
struct tcp6_l2_buf_t {
#ifdef __AVX2__
	uint8_t pad[14];	/* 0	align ip6h to 32 bytes */
#else
	uint8_t pad[2];		/*	align ip6h to 4 bytes	0 */
#endif
	struct tap_hdr taph;	/* 14				2 */
	struct ipv6hdr ip6h;	/* 32				20 */
	struct tcphdr th;	/* 72				60 */
	uint8_t data[MSS6];	/* 92				80 */
				/* 65536			65532 */
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
tcp6_l2_buf[TCP_FRAMES_MEM];

static unsigned int tcp6_l2_buf_used;

/* recvmsg()/sendmsg() data for tap */
static char 		tcp_buf_discard		[MAX_WINDOW];
static struct iovec	iov_sock		[TCP_FRAMES_MEM + 1];

static struct iovec	tcp4_l2_iov		[TCP_FRAMES_MEM];
static struct iovec	tcp6_l2_iov		[TCP_FRAMES_MEM];
static struct iovec	tcp4_l2_flags_iov	[TCP_FRAMES_MEM];
static struct iovec	tcp6_l2_flags_iov	[TCP_FRAMES_MEM];

static struct mmsghdr	tcp_l2_mh		[TCP_FRAMES_MEM];

/* sendmsg() to socket */
static struct iovec	tcp_iov			[UIO_MAXIOV];

/**
 * tcp4_l2_flags_buf_t - IPv4 packet buffers for segments without data (flags)
 * @psum:	Partial IP header checksum (excluding tot_len and saddr)
 * @tsum:	Partial TCP header checksum (excluding length and saddr)
 * @pad:	Align TCP header to 32 bytes, for AVX2 checksum calculation only
 * @taph:	Tap-level headers (partially pre-filled)
 * @iph:	Pre-filled IP header (except for tot_len and saddr)
 * @th:		Headroom for TCP header
 * @opts:	Headroom for TCP options
 */
static struct tcp4_l2_flags_buf_t {
	uint32_t psum;		/* 0 */
	uint32_t tsum;		/* 4 */
#ifdef __AVX2__
	uint8_t pad[18];	/* 8, align th to 32 bytes */
#else
	uint8_t pad[2];		/*	align iph to 4 bytes	8 */
#endif
	struct tap_hdr taph;	/* 26				10 */
	struct iphdr iph;	/* 44				28 */
	struct tcphdr th;	/* 64				48 */
	char opts[OPT_MSS_LEN + OPT_WS_LEN + 1];
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
tcp4_l2_flags_buf[TCP_FRAMES_MEM];

static unsigned int tcp4_l2_flags_buf_used;

/**
 * tcp6_l2_flags_buf_t - IPv6 packet buffers for segments without data (flags)
 * @pad:	Align IPv6 header for checksum calculation to 32B (AVX2) or 4B
 * @taph:	Tap-level headers (partially pre-filled)
 * @ip6h:	Pre-filled IP header (except for payload_len and addresses)
 * @th:		Headroom for TCP header
 * @opts:	Headroom for TCP options
 */
static struct tcp6_l2_flags_buf_t {
#ifdef __AVX2__
	uint8_t pad[14];	/* 0	align ip6h to 32 bytes */
#else
	uint8_t pad[2];		/*	align ip6h to 4 bytes		   0 */
#endif
	struct tap_hdr taph;	/* 14					   2 */
	struct ipv6hdr ip6h;	/* 32					  20 */
	struct tcphdr th	/* 72 */ __attribute__ ((aligned(4))); /* 60 */
	char opts[OPT_MSS_LEN + OPT_WS_LEN + 1];
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
tcp6_l2_flags_buf[TCP_FRAMES_MEM];

static unsigned int tcp6_l2_flags_buf_used;

/* TCP connections */
union tcp_conn tc[TCP_MAX_CONNS];

#define CONN(index)		(&tc[(index)].tap)
#define CONN_IDX(conn)		((union tcp_conn *)(conn) - tc)

/** conn_at_idx() - Find a connection by index, if present
 * @index:	Index of connection to lookup
 *
 * Return: pointer to connection, or NULL if @index is out of bounds
 */
static inline struct tcp_tap_conn *conn_at_idx(int index)
{
	if ((index < 0) || (index >= TCP_MAX_CONNS))
		return NULL;
	ASSERT(!(CONN(index)->c.spliced));
	return CONN(index);
}

/* Table for lookup from remote address, local port, remote port */
static struct tcp_tap_conn *tc_hash[TCP_HASH_TABLE_SIZE];

/* Pools for pre-opened sockets (in init) */
int init_sock_pool4		[TCP_SOCK_POOL_SIZE];
int init_sock_pool6		[TCP_SOCK_POOL_SIZE];

/**
 * tcp_conn_epoll_events() - epoll events mask for given connection state
 * @events:	Current connection events
 * @conn_flags	Connection flags
 *
 * Return: epoll events mask corresponding to implied connection state
 */
static uint32_t tcp_conn_epoll_events(uint8_t events, uint8_t conn_flags)
{
	if (!events)
		return 0;

	if (events & ESTABLISHED) {
		if (events & TAP_FIN_SENT)
			return EPOLLET;

		if (conn_flags & STALLED)
			return EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;

		return EPOLLIN | EPOLLRDHUP;
	}

	if (events == TAP_SYN_RCVD)
		return EPOLLOUT | EPOLLET | EPOLLRDHUP;

	return EPOLLRDHUP;
}

static void conn_flag_do(const struct ctx *c, struct tcp_tap_conn *conn,
			 unsigned long flag);
#define conn_flag(c, conn, flag)					\
	do {								\
		trace("TCP: flag at %s:%i", __func__, __LINE__);	\
		conn_flag_do(c, conn, flag);				\
	} while (0)

/**
 * tcp_epoll_ctl() - Add/modify/delete epoll state from connection events
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, negative error code on failure (not on deletion)
 */
static int tcp_epoll_ctl(const struct ctx *c, struct tcp_tap_conn *conn)
{
	int m = conn->c.in_epoll ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	union epoll_ref ref = { .r.proto = IPPROTO_TCP, .r.s = conn->sock,
				.r.p.tcp.tcp.index = CONN_IDX(conn) };
	struct epoll_event ev = { .data.u64 = ref.u64 };

	if (conn->events == CLOSED) {
		if (conn->c.in_epoll)
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->sock, &ev);
		if (conn->timer != -1)
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->timer, &ev);
		return 0;
	}

	ev.events = tcp_conn_epoll_events(conn->events, conn->flags);

	if (epoll_ctl(c->epollfd, m, conn->sock, &ev))
		return -errno;

	conn->c.in_epoll = true;

	if (conn->timer != -1) {
		union epoll_ref ref_t = { .r.proto = IPPROTO_TCP,
					  .r.s = conn->sock,
					  .r.p.tcp.tcp.timer = 1,
					  .r.p.tcp.tcp.index = CONN_IDX(conn) };
		struct epoll_event ev_t = { .data.u64 = ref_t.u64,
					    .events = EPOLLIN | EPOLLET };

		if (epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->timer, &ev_t))
			return -errno;
	}

	return 0;
}

/**
 * tcp_timer_ctl() - Set timerfd based on flags/events, create timerfd if needed
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * #syscalls timerfd_create timerfd_settime
 */
static void tcp_timer_ctl(const struct ctx *c, struct tcp_tap_conn *conn)
{
	struct itimerspec it = { { 0 }, { 0 } };

	if (conn->events == CLOSED)
		return;

	if (conn->timer == -1) {
		union epoll_ref ref = { .r.proto = IPPROTO_TCP,
					.r.s = conn->sock,
					.r.p.tcp.tcp.timer = 1,
					.r.p.tcp.tcp.index = CONN_IDX(conn) };
		struct epoll_event ev = { .data.u64 = ref.u64,
					  .events = EPOLLIN | EPOLLET };
		int fd;

		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd == -1 || fd > SOCKET_MAX) {
			debug("TCP: failed to get timer: %s", strerror(errno));
			if (fd > -1)
				close(fd);
			conn->timer = -1;
			return;
		}
		conn->timer = fd;

		if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->timer, &ev)) {
			debug("TCP: failed to add timer: %s", strerror(errno));
			close(conn->timer);
			conn->timer = -1;
			return;
		}
	}

	if (conn->flags & ACK_TO_TAP_DUE) {
		it.it_value.tv_nsec = (long)ACK_INTERVAL * 1000 * 1000;
	} else if (conn->flags & ACK_FROM_TAP_DUE) {
		if (!(conn->events & ESTABLISHED))
			it.it_value.tv_sec = SYN_TIMEOUT;
		else
			it.it_value.tv_sec = ACK_TIMEOUT;
	} else if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED)) {
		it.it_value.tv_sec = FIN_TIMEOUT;
	} else {
		it.it_value.tv_sec = ACT_TIMEOUT;
	}

	debug("TCP: index %li, timer expires in %lu.%03lus", CONN_IDX(conn),
	      it.it_value.tv_sec, it.it_value.tv_nsec / 1000 / 1000);

	timerfd_settime(conn->timer, 0, &it, NULL);
}

/**
 * conn_flag_do() - Set/unset given flag, log, update epoll on STALLED flag
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flag:	Flag to set, or ~flag to unset
 */
static void conn_flag_do(const struct ctx *c, struct tcp_tap_conn *conn,
			 unsigned long flag)
{
	if (flag & (flag - 1)) {
		int flag_index = fls(~flag);

		if (!(conn->flags & ~flag))
			return;

		conn->flags &= flag;
		if (flag_index >= 0) {
			debug("TCP: index %li: %s dropped", CONN_IDX(conn),
			      tcp_flag_str[flag_index]);
		}
	} else {
		int flag_index = fls(flag);

		if (conn->flags & flag) {
			/* Special case: setting ACK_FROM_TAP_DUE on a
			 * connection where it's already set is used to
			 * re-schedule the existing timer.
			 * TODO: define clearer semantics for timer-related
			 * flags and factor this into the logic below.
			 */
			if (flag == ACK_FROM_TAP_DUE)
				tcp_timer_ctl(c, conn);

			return;
		}

		conn->flags |= flag;
		if (flag_index >= 0) {
			debug("TCP: index %li: %s", CONN_IDX(conn),
			      tcp_flag_str[flag_index]);
		}
	}

	if (flag == STALLED || flag == ~STALLED)
		tcp_epoll_ctl(c, conn);

	if (flag == ACK_FROM_TAP_DUE || flag == ACK_TO_TAP_DUE		  ||
	    (flag == ~ACK_FROM_TAP_DUE && (conn->flags & ACK_TO_TAP_DUE)) ||
	    (flag == ~ACK_TO_TAP_DUE   && (conn->flags & ACK_FROM_TAP_DUE)))
		tcp_timer_ctl(c, conn);
}

/**
 * conn_event_do() - Set and log connection events, update epoll state
 * @c:		Execution context
 * @conn:	Connection pointer
 * @event:	Connection event
 */
static void conn_event_do(const struct ctx *c, struct tcp_tap_conn *conn,
			  unsigned long event)
{
	int prev, new, num = fls(event);

	if (conn->events & event)
		return;

	prev = fls(conn->events);
	if (conn->flags & ACTIVE_CLOSE)
		prev += 5;

	if ((conn->events & ESTABLISHED) && (conn->events != ESTABLISHED))
		prev++;		/* i.e. SOCK_FIN_RCVD, not TAP_SYN_ACK_SENT */

	if (event == CLOSED || (event & CONN_STATE_BITS))
		conn->events = event;
	else
		conn->events |= event;

	new = fls(conn->events);

	if ((conn->events & ESTABLISHED) && (conn->events != ESTABLISHED)) {
		num++;
		new++;
	}
	if (conn->flags & ACTIVE_CLOSE)
		new += 5;

	if (prev != new) {
		debug("TCP: index %li, %s: %s -> %s", CONN_IDX(conn),
		      num == -1 	       ? "CLOSED" : tcp_event_str[num],
		      prev == -1	       ? "CLOSED" : tcp_state_str[prev],
		      (new == -1 || num == -1) ? "CLOSED" : tcp_state_str[new]);
	} else {
		debug("TCP: index %li, %s", CONN_IDX(conn),
		      num == -1 	       ? "CLOSED" : tcp_event_str[num]);
	}

	if ((event == TAP_FIN_RCVD) && !(conn->events & SOCK_FIN_RCVD))
		conn_flag(c, conn, ACTIVE_CLOSE);
	else
		tcp_epoll_ctl(c, conn);

	if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED))
		tcp_timer_ctl(c, conn);
}

#define conn_event(c, conn, event)					\
	do {								\
		trace("TCP: event at %s:%i", __func__, __LINE__);	\
		conn_event_do(c, conn, event);				\
	} while (0)

/**
 * tcp_rtt_dst_low() - Check if low RTT was seen for connection endpoint
 * @conn:	Connection pointer
 *
 * Return: 1 if destination is in low RTT table, 0 otherwise
 */
static int tcp_rtt_dst_low(const struct tcp_tap_conn *conn)
{
	int i;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++)
		if (inany_equals(&conn->addr, low_rtt_dst + i))
			return 1;

	return 0;
}

/**
 * tcp_rtt_dst_check() - Check tcpi_min_rtt, insert endpoint in table if low
 * @conn:	Connection pointer
 * @tinfo:	Pointer to struct tcp_info for socket
 */
static void tcp_rtt_dst_check(const struct tcp_tap_conn *conn,
			      const struct tcp_info *tinfo)
{
#ifdef HAS_MIN_RTT
	int i, hole = -1;

	if (!tinfo->tcpi_min_rtt ||
	    (int)tinfo->tcpi_min_rtt > LOW_RTT_THRESHOLD)
		return;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++) {
		if (inany_equals(&conn->addr, low_rtt_dst + i))
			return;
		if (hole == -1 && IN6_IS_ADDR_UNSPECIFIED(low_rtt_dst + i))
			hole = i;
	}

	/* Keep gcc 12 happy: this won't actually happen because the table is
	 * guaranteed to have a hole, see the second memcpy() below.
	 */
	if (hole == -1)
		return;

	low_rtt_dst[hole++] = conn->addr;
	if (hole == LOW_RTT_TABLE_SIZE)
		hole = 0;
	inany_from_af(low_rtt_dst + hole, AF_INET6, &in6addr_any);
#else
	(void)conn;
	(void)tinfo;
#endif /* HAS_MIN_RTT */
}

/**
 * tcp_get_sndbuf() - Get, scale SO_SNDBUF between thresholds (1 to 0.5 usage)
 * @conn:	Connection pointer
 */
static void tcp_get_sndbuf(struct tcp_tap_conn *conn)
{
	int s = conn->sock, sndbuf;
	socklen_t sl;
	uint64_t v;

	sl = sizeof(sndbuf);
	if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sl)) {
		SNDBUF_SET(conn, WINDOW_DEFAULT);
		return;
	}

	v = sndbuf;
	if (v >= SNDBUF_BIG)
		v /= 2;
	else if (v > SNDBUF_SMALL)
		v -= v * (v - SNDBUF_SMALL) / (SNDBUF_BIG - SNDBUF_SMALL) / 2;

	SNDBUF_SET(conn, MIN(INT_MAX, v));
}

/**
 * tcp_sock_set_bufsize() - Set SO_RCVBUF and SO_SNDBUF to maximum values
 * @s:		Socket, can be -1 to avoid check in the caller
 */
void tcp_sock_set_bufsize(const struct ctx *c, int s)
{
	int v = INT_MAX / 2; /* Kernel clamps and rounds, no need to check */

	if (s == -1)
		return;

	if (!c->low_rmem && setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)))
		trace("TCP: failed to set SO_RCVBUF to %i", v);

	if (!c->low_wmem && setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)))
		trace("TCP: failed to set SO_SNDBUF to %i", v);
}

/**
 * tcp_update_check_ip4() - Update IPv4 with variable parts from stored one
 * @buf:	L2 packet buffer with final IPv4 header
 */
static void tcp_update_check_ip4(struct tcp4_l2_buf_t *buf)
{
	uint32_t sum = buf->psum;

	sum += buf->iph.tot_len;
	sum += (buf->iph.saddr >> 16) & 0xffff;
	sum += buf->iph.saddr & 0xffff;

	buf->iph.check = (uint16_t)~csum_fold(sum);
}

/**
 * tcp_update_check_tcp4() - Update TCP checksum from stored one
 * @buf:	L2 packet buffer with final IPv4 header
 */
static void tcp_update_check_tcp4(struct tcp4_l2_buf_t *buf)
{
	uint16_t tlen = ntohs(buf->iph.tot_len) - 20;
	uint32_t sum = buf->tsum;

	sum += (buf->iph.saddr >> 16) & 0xffff;
	sum += buf->iph.saddr & 0xffff;
	sum += htons(ntohs(buf->iph.tot_len) - 20);

	buf->th.check = 0;
	buf->th.check = csum(&buf->th, tlen, sum);
}

/**
 * tcp_update_check_tcp6() - Calculate TCP checksum for IPv6
 * @buf:	L2 packet buffer with final IPv6 header
 */
static void tcp_update_check_tcp6(struct tcp6_l2_buf_t *buf)
{
	int len = ntohs(buf->ip6h.payload_len) + sizeof(struct ipv6hdr);

	buf->ip6h.hop_limit = IPPROTO_TCP;
	buf->ip6h.version = 0;
	buf->ip6h.nexthdr = 0;

	buf->th.check = 0;
	buf->th.check = csum(&buf->ip6h, len, 0);

	buf->ip6h.hop_limit = 255;
	buf->ip6h.version = 6;
	buf->ip6h.nexthdr = IPPROTO_TCP;
}

/**
 * tcp_update_l2_buf() - Update L2 buffers with Ethernet and IPv4 addresses
 * @eth_d:	Ethernet destination address, NULL if unchanged
 * @eth_s:	Ethernet source address, NULL if unchanged
 * @ip_da:	Pointer to IPv4 destination address, NULL if unchanged
 */
void tcp_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s,
		       const struct in_addr *ip_da)
{
	int i;

	for (i = 0; i < TCP_FRAMES_MEM; i++) {
		struct tcp4_l2_flags_buf_t *b4f = &tcp4_l2_flags_buf[i];
		struct tcp6_l2_flags_buf_t *b6f = &tcp6_l2_flags_buf[i];
		struct tcp4_l2_buf_t *b4 = &tcp4_l2_buf[i];
		struct tcp6_l2_buf_t *b6 = &tcp6_l2_buf[i];

		tap_update_mac(&b4->taph, eth_d, eth_s);
		tap_update_mac(&b6->taph, eth_d, eth_s);
		tap_update_mac(&b4f->taph, eth_d, eth_s);
		tap_update_mac(&b6f->taph, eth_d, eth_s);

		if (ip_da) {
			b4f->iph.daddr = b4->iph.daddr = ip_da->s_addr;
			if (!i) {
				b4f->iph.saddr = b4->iph.saddr = 0;
				b4f->iph.tot_len = b4->iph.tot_len = 0;
				b4f->iph.check = b4->iph.check = 0;
				b4f->psum = b4->psum = sum_16b(&b4->iph, 20);

				b4->tsum = ((ip_da->s_addr >> 16) & 0xffff) +
					    (ip_da->s_addr & 0xffff) +
					    htons(IPPROTO_TCP);
				b4f->tsum = b4->tsum;
			} else {
				b4f->psum = b4->psum = tcp4_l2_buf[0].psum;
				b4f->tsum = b4->tsum = tcp4_l2_buf[0].tsum;
			}
		}
	}
}

/**
 * tcp_sock4_iov_init() - Initialise scatter-gather L2 buffers for IPv4 sockets
 * @c:		Execution context
 */
static void tcp_sock4_iov_init(const struct ctx *c)
{
	struct iovec *iov;
	int i;

	for (i = 0; i < ARRAY_SIZE(tcp4_l2_buf); i++) {
		tcp4_l2_buf[i] = (struct tcp4_l2_buf_t) {
			.taph = TAP_HDR_INIT(ETH_P_IP),
			.iph = L2_BUF_IP4_INIT(IPPROTO_TCP),
			.th = { .doff = sizeof(struct tcphdr) / 4, .ack = 1 }
		};
	}

	for (i = 0; i < ARRAY_SIZE(tcp4_l2_flags_buf); i++) {
		tcp4_l2_flags_buf[i] = (struct tcp4_l2_flags_buf_t) {
			.taph = TAP_HDR_INIT(ETH_P_IP),
			.iph = L2_BUF_IP4_INIT(IPPROTO_TCP)
		};
	}

	for (i = 0, iov = tcp4_l2_iov; i < TCP_FRAMES_MEM; i++, iov++)
		iov->iov_base = tap_iov_base(c, &tcp4_l2_buf[i].taph);

	for (i = 0, iov = tcp4_l2_flags_iov; i < TCP_FRAMES_MEM; i++, iov++)
		iov->iov_base = tap_iov_base(c, &tcp4_l2_flags_buf[i].taph);
}

/**
 * tcp_sock6_iov_init() - Initialise scatter-gather L2 buffers for IPv6 sockets
 * @c:		Execution context
 */
static void tcp_sock6_iov_init(const struct ctx *c)
{
	struct iovec *iov;
	int i;

	for (i = 0; i < ARRAY_SIZE(tcp6_l2_buf); i++) {
		tcp6_l2_buf[i] = (struct tcp6_l2_buf_t) {
			.taph = TAP_HDR_INIT(ETH_P_IPV6),
			.ip6h = L2_BUF_IP6_INIT(IPPROTO_TCP),
			.th = { .doff = sizeof(struct tcphdr) / 4, .ack = 1 }
		};
	}

	for (i = 0; i < ARRAY_SIZE(tcp6_l2_flags_buf); i++) {
		tcp6_l2_flags_buf[i] = (struct tcp6_l2_flags_buf_t) {
			.taph = TAP_HDR_INIT(ETH_P_IPV6),
			.ip6h = L2_BUF_IP6_INIT(IPPROTO_TCP)
		};
	}

	for (i = 0, iov = tcp6_l2_iov; i < TCP_FRAMES_MEM; i++, iov++)
		iov->iov_base = tap_iov_base(c, &tcp6_l2_buf[i].taph);

	for (i = 0, iov = tcp6_l2_flags_iov; i < TCP_FRAMES_MEM; i++, iov++)
		iov->iov_base = tap_iov_base(c, &tcp6_l2_flags_buf[i].taph);
}

/**
 * tcp_opt_get() - Get option, and value if any, from TCP header
 * @opts:	Pointer to start of TCP options in header
 * @len:	Length of buffer, excluding TCP header -- NOT checked here!
 * @type_find:	Option type to look for
 * @optlen_set:	Optional, filled with option length if passed
 * @value_set:	Optional, set to start of option value if passed
 *
 * Return: option value, meaningful for up to 4 bytes, -1 if not found
 */
static int tcp_opt_get(const char *opts, size_t len, uint8_t type_find,
		       uint8_t *optlen_set, const char **value_set)
{
	uint8_t type, optlen;

	if (!opts || !len)
		return -1;

	for (; len >= 2; opts += optlen, len -= optlen) {
		switch (*opts) {
		case OPT_EOL:
			return -1;
		case OPT_NOP:
			optlen = 1;
			break;
		default:
			type = *(opts++);

			if (*(uint8_t *)opts < 2 || *(uint8_t *)opts > len)
				return -1;

			optlen = *(opts++) - 2;
			len -= 2;

			if (type != type_find)
				break;

			if (optlen_set)
				*optlen_set = optlen;
			if (value_set)
				*value_set = opts;

			switch (optlen) {
			case 0:
				return 0;
			case 1:
				return *opts;
			case 2:
				return ntohs(*(uint16_t *)opts);
			default:
				return ntohl(*(uint32_t *)opts);
			}
		}
	}

	return -1;
}

/**
 * tcp_hash_match() - Check if a connection entry matches address and ports
 * @conn:	Connection entry to match against
 * @addr:	Remote address
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: 1 on match, 0 otherwise
 */
static int tcp_hash_match(const struct tcp_tap_conn *conn,
			  const union inany_addr *addr,
			  in_port_t tap_port, in_port_t sock_port)
{
	if (inany_equals(&conn->addr, addr) &&
	    conn->tap_port == tap_port && conn->sock_port == sock_port)
		return 1;

	return 0;
}

/**
 * tcp_hash() - Calculate hash value for connection given address and ports
 * @c:		Execution context
 * @addr:	Remote address
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: hash value, already modulo size of the hash table
 */
static unsigned int tcp_hash(const struct ctx *c, const union inany_addr *addr,
			     in_port_t tap_port, in_port_t sock_port)
{
	struct {
		union inany_addr addr;
		in_port_t tap_port;
		in_port_t sock_port;
	} __attribute__((__packed__)) in = {
		*addr, tap_port, sock_port
	};
	uint64_t b = 0;

	b = siphash_20b((uint8_t *)&in, c->tcp.hash_secret);

	return (unsigned int)(b % TCP_HASH_TABLE_SIZE);
}

/**
 * tcp_conn_hash() - Calculate hash bucket of an existing connection
 * @c:		Execution context
 * @conn:	Connection
 *
 * Return: hash value, already modulo size of the hash table
 */
static unsigned int tcp_conn_hash(const struct ctx *c,
				  const struct tcp_tap_conn *conn)
{
	return tcp_hash(c, &conn->addr, conn->tap_port, conn->sock_port);
}

/**
 * tcp_hash_insert() - Insert connection into hash table, chain link
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_hash_insert(const struct ctx *c, struct tcp_tap_conn *conn)
{
	int b;

	b = tcp_hash(c, &conn->addr, conn->tap_port, conn->sock_port);
	conn->next_index = tc_hash[b] ? CONN_IDX(tc_hash[b]) : -1;
	tc_hash[b] = conn;

	debug("TCP: hash table insert: index %li, sock %i, bucket: %i, next: "
	      "%p", CONN_IDX(conn), conn->sock, b, conn_at_idx(conn->next_index));
}

/**
 * tcp_hash_remove() - Drop connection from hash table, chain unlink
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_hash_remove(const struct ctx *c,
			    const struct tcp_tap_conn *conn)
{
	struct tcp_tap_conn *entry, *prev = NULL;
	int b = tcp_conn_hash(c, conn);

	for (entry = tc_hash[b]; entry;
	     prev = entry, entry = conn_at_idx(entry->next_index)) {
		if (entry == conn) {
			if (prev)
				prev->next_index = conn->next_index;
			else
				tc_hash[b] = conn_at_idx(conn->next_index);
			break;
		}
	}

	debug("TCP: hash table remove: index %li, sock %i, bucket: %i, new: %p",
	      CONN_IDX(conn), conn->sock, b,
	      prev ? conn_at_idx(prev->next_index) : tc_hash[b]);
}

/**
 * tcp_tap_conn_update() - Update tcp_tap_conn when being moved in the table
 * @c:		Execution context
 * @old:	Old location of tcp_tap_conn
 * @new:	New location of tcp_tap_conn
 */
static void tcp_tap_conn_update(struct ctx *c, struct tcp_tap_conn *old,
				struct tcp_tap_conn *new)
{
	struct tcp_tap_conn *entry, *prev = NULL;
	int b = tcp_conn_hash(c, old);

	for (entry = tc_hash[b]; entry;
	     prev = entry, entry = conn_at_idx(entry->next_index)) {
		if (entry == old) {
			if (prev)
				prev->next_index = CONN_IDX(new);
			else
				tc_hash[b] = new;
			break;
		}
	}

	debug("TCP: hash table update: old index %li, new index %li, sock %i, "
	      "bucket: %i, old: %p, new: %p",
	      CONN_IDX(old), CONN_IDX(new), new->sock, b, old, new);

	tcp_epoll_ctl(c, new);
}

/**
 * tcp_hash_lookup() - Look up connection given remote address and ports
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to in_addr or in6_addr
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: connection pointer, if found, -ENOENT otherwise
 */
static struct tcp_tap_conn *tcp_hash_lookup(const struct ctx *c,
					    int af, const void *addr,
					    in_port_t tap_port,
					    in_port_t sock_port)
{
	union inany_addr aany;
	struct tcp_tap_conn *conn;
	int b;

	inany_from_af(&aany, af, addr);
	b = tcp_hash(c, &aany, tap_port, sock_port);
	for (conn = tc_hash[b]; conn; conn = conn_at_idx(conn->next_index)) {
		if (tcp_hash_match(conn, &aany, tap_port, sock_port))
			return conn;
	}

	return NULL;
}

/**
 * tcp_table_compact() - Perform compaction on connection table
 * @c:		Execution context
 * @hole:	Pointer to recently closed connection
 */
void tcp_table_compact(struct ctx *c, union tcp_conn *hole)
{
	union tcp_conn *from;

	if (CONN_IDX(hole) == --c->tcp.conn_count) {
		debug("TCP: table compaction: maximum index was %li (%p)",
		      CONN_IDX(hole), hole);
		memset(hole, 0, sizeof(*hole));
		return;
	}

	from = tc + c->tcp.conn_count;
	memcpy(hole, from, sizeof(*hole));

	if (from->c.spliced)
		tcp_splice_conn_update(c, &hole->splice);
	else
		tcp_tap_conn_update(c, &from->tap, &hole->tap);

	debug("TCP: table compaction (spliced=%d): old index %li, new index %li, "
	      "from: %p, to: %p",
	      from->c.spliced, CONN_IDX(from), CONN_IDX(hole), from, hole);

	memset(from, 0, sizeof(*from));
}

/**
 * tcp_conn_destroy() - Close sockets, trigger hash table removal and compaction
 * @c:		Execution context
 * @conn_union:	Connection pointer (container union)
 */
static void tcp_conn_destroy(struct ctx *c, union tcp_conn *conn_union)
{
	struct tcp_tap_conn *conn = &conn_union->tap;

	close(conn->sock);
	if (conn->timer != -1)
		close(conn->timer);

	tcp_hash_remove(c, conn);
	tcp_table_compact(c, conn_union);
}

static void tcp_rst_do(struct ctx *c, struct tcp_tap_conn *conn);
#define tcp_rst(c, conn)						\
	do {								\
		debug("TCP: index %li, reset at %s:%i", CONN_IDX(conn), \
		      __func__, __LINE__);				\
		tcp_rst_do(c, conn);					\
	} while (0)

/**
 * tcp_l2_flags_buf_flush() - Send out buffers for segments with no data (flags)
 * @c:		Execution context
 */
static void tcp_l2_flags_buf_flush(struct ctx *c)
{
	tap_send_frames(c, tcp6_l2_flags_iov, tcp6_l2_flags_buf_used);
	tcp6_l2_flags_buf_used = 0;

	tap_send_frames(c, tcp4_l2_flags_iov, tcp4_l2_flags_buf_used);
	tcp4_l2_flags_buf_used = 0;
}

/**
 * tcp_l2_data_buf_flush() - Send out buffers for segments with data
 * @c:		Execution context
 */
static void tcp_l2_data_buf_flush(struct ctx *c)
{
	tap_send_frames(c, tcp6_l2_iov, tcp6_l2_buf_used);
	tcp6_l2_buf_used = 0;

	tap_send_frames(c, tcp4_l2_iov, tcp4_l2_buf_used);
	tcp4_l2_buf_used = 0;
}

/**
 * tcp_defer_handler() - Handler for TCP deferred tasks
 * @c:		Execution context
 */
void tcp_defer_handler(struct ctx *c)
{
	int max_conns = c->tcp.conn_count / 100 * TCP_CONN_PRESSURE;
	int max_files = c->nofile / 100 * TCP_FILE_PRESSURE;
	union tcp_conn *conn;

	tcp_l2_flags_buf_flush(c);
	tcp_l2_data_buf_flush(c);

	if ((c->tcp.conn_count < MIN(max_files, max_conns)) &&
	    (c->tcp.splice_conn_count < MIN(max_files / 6, max_conns)))
		return;

	for (conn = tc + c->tcp.conn_count - 1; conn >= tc; conn--) {
		if (conn->c.spliced) {
			if (conn->splice.flags & CLOSING)
				tcp_splice_destroy(c, conn);
		} else {
			if (conn->tap.events == CLOSED)
				tcp_conn_destroy(c, conn);
		}
	}
}

/**
 * tcp_l2_buf_fill_headers() - Fill 802.3, IP, TCP headers in pre-cooked buffers
 * @c:		Execution context
 * @conn:	Connection pointer
 * @p:		Pointer to any type of TCP pre-cooked buffer
 * @plen:	Payload length (including TCP header options)
 * @check:	Checksum, if already known
 * @seq:	Sequence number for this segment
 *
 * Return: frame length including L2 headers, host order
 */
static size_t tcp_l2_buf_fill_headers(const struct ctx *c,
				      const struct tcp_tap_conn *conn,
				      void *p, size_t plen,
				      const uint16_t *check, uint32_t seq)
{
	const struct in_addr *a4 = inany_v4(&conn->addr);
	size_t ip_len, tlen;

#define SET_TCP_HEADER_COMMON_V4_V6(b, conn, seq)			\
do {									\
	b->th.source = htons(conn->sock_port);				\
	b->th.dest = htons(conn->tap_port);				\
	b->th.seq = htonl(seq);						\
	b->th.ack_seq = htonl(conn->seq_ack_to_tap);			\
	if (conn->events & ESTABLISHED)	{				\
		b->th.window = htons(conn->wnd_to_tap);			\
	} else {							\
		unsigned wnd = conn->wnd_to_tap << conn->ws_to_tap;	\
									\
		b->th.window = htons(MIN(wnd, USHRT_MAX));		\
	}								\
} while (0)

	if (a4) {
		struct tcp4_l2_buf_t *b = (struct tcp4_l2_buf_t *)p;

		ip_len = plen + sizeof(struct iphdr) + sizeof(struct tcphdr);
		b->iph.tot_len = htons(ip_len);
		b->iph.saddr = a4->s_addr;
		b->iph.daddr = c->ip4.addr_seen.s_addr;

		if (check)
			b->iph.check = *check;
		else
			tcp_update_check_ip4(b);

		SET_TCP_HEADER_COMMON_V4_V6(b, conn, seq);

		tcp_update_check_tcp4(b);

		tlen = tap_iov_len(c, &b->taph, ip_len);
	} else {
		struct tcp6_l2_buf_t *b = (struct tcp6_l2_buf_t *)p;

		ip_len = plen + sizeof(struct ipv6hdr) + sizeof(struct tcphdr);

		b->ip6h.payload_len = htons(plen + sizeof(struct tcphdr));
		b->ip6h.saddr = conn->addr.a6;
		if (IN6_IS_ADDR_LINKLOCAL(&b->ip6h.saddr))
			b->ip6h.daddr = c->ip6.addr_ll_seen;
		else
			b->ip6h.daddr = c->ip6.addr_seen;

		memset(b->ip6h.flow_lbl, 0, 3);

		SET_TCP_HEADER_COMMON_V4_V6(b, conn, seq);

		tcp_update_check_tcp6(b);

		b->ip6h.flow_lbl[0] = (conn->sock >> 16) & 0xf;
		b->ip6h.flow_lbl[1] = (conn->sock >> 8) & 0xff;
		b->ip6h.flow_lbl[2] = (conn->sock >> 0) & 0xff;

		tlen = tap_iov_len(c, &b->taph, ip_len);
	}
#undef SET_TCP_HEADER_COMMON_V4_V6

	return tlen;
}

/**
 * tcp_update_seqack_wnd() - Update ACK sequence and window to guest/tap
 * @c:		Execution context
 * @conn:	Connection pointer
 * @force_seq:	Force ACK sequence to latest segment, instead of checking socket
 * @tinfo:	tcp_info from kernel, can be NULL if not pre-fetched
 *
 * Return: 1 if sequence or window were updated, 0 otherwise
 */
static int tcp_update_seqack_wnd(const struct ctx *c, struct tcp_tap_conn *conn,
				 int force_seq, struct tcp_info *tinfo)
{
	uint32_t prev_wnd_to_tap = conn->wnd_to_tap << conn->ws_to_tap;
	uint32_t prev_ack_to_tap = conn->seq_ack_to_tap;
	/* cppcheck-suppress [ctunullpointer, unmatchedSuppression] */
	socklen_t sl = sizeof(*tinfo);
	struct tcp_info tinfo_new;
	uint32_t new_wnd_to_tap = prev_wnd_to_tap;
	int s = conn->sock;

#ifndef HAS_BYTES_ACKED
	(void)force_seq;

	conn->seq_ack_to_tap = conn->seq_from_tap;
	if (SEQ_LT(conn->seq_ack_to_tap, prev_ack_to_tap))
		conn->seq_ack_to_tap = prev_ack_to_tap;
#else
	if ((unsigned)SNDBUF_GET(conn) < SNDBUF_SMALL || tcp_rtt_dst_low(conn)
	    || CONN_IS_CLOSING(conn) || (conn->flags & LOCAL) || force_seq) {
		conn->seq_ack_to_tap = conn->seq_from_tap;
	} else if (conn->seq_ack_to_tap != conn->seq_from_tap) {
		if (!tinfo) {
			tinfo = &tinfo_new;
			if (getsockopt(s, SOL_TCP, TCP_INFO, tinfo, &sl))
				return 0;
		}

		conn->seq_ack_to_tap = tinfo->tcpi_bytes_acked +
				       conn->seq_init_from_tap;

		if (SEQ_LT(conn->seq_ack_to_tap, prev_ack_to_tap))
			conn->seq_ack_to_tap = prev_ack_to_tap;
	}
#endif /* !HAS_BYTES_ACKED */

	if (!KERNEL_REPORTS_SND_WND(c)) {
		tcp_get_sndbuf(conn);
		new_wnd_to_tap = MIN(SNDBUF_GET(conn), MAX_WINDOW);
		conn->wnd_to_tap = MIN(new_wnd_to_tap >> conn->ws_to_tap,
				       USHRT_MAX);
		goto out;
	}

	if (!tinfo) {
		if (prev_wnd_to_tap > WINDOW_DEFAULT) {
			goto out;
}
		tinfo = &tinfo_new;
		if (getsockopt(s, SOL_TCP, TCP_INFO, tinfo, &sl)) {
			goto out;
}
	}

#ifdef HAS_SND_WND
	if ((conn->flags & LOCAL) || tcp_rtt_dst_low(conn)) {
		new_wnd_to_tap = tinfo->tcpi_snd_wnd;
	} else {
		tcp_get_sndbuf(conn);
		new_wnd_to_tap = MIN((int)tinfo->tcpi_snd_wnd,
				     SNDBUF_GET(conn));
	}
#endif

	new_wnd_to_tap = MIN(new_wnd_to_tap, MAX_WINDOW);
	if (!(conn->events & ESTABLISHED))
		new_wnd_to_tap = MAX(new_wnd_to_tap, WINDOW_DEFAULT);

	conn->wnd_to_tap = MIN(new_wnd_to_tap >> conn->ws_to_tap, USHRT_MAX);

	if (!conn->wnd_to_tap)
		conn_flag(c, conn, ACK_TO_TAP_DUE);

out:
	return new_wnd_to_tap       != prev_wnd_to_tap ||
	       conn->seq_ack_to_tap != prev_ack_to_tap;
}

/**
 * tcp_update_seqack_from_tap() - ACK number from tap and related flags/counters
 * @c:		Execution context
 * @conn:	Connection pointer
 * @seq		Current ACK sequence, host order
 */
static void tcp_update_seqack_from_tap(const struct ctx *c,
				       struct tcp_tap_conn *conn, uint32_t seq)
{
	if (SEQ_GT(seq, conn->seq_ack_from_tap)) {
		if (seq == conn->seq_to_tap)
			conn_flag(c, conn, ~ACK_FROM_TAP_DUE);
		else
			conn_flag(c, conn, ACK_FROM_TAP_DUE);

		conn->retrans = 0;
		conn->seq_ack_from_tap = seq;
	}
}

/**
 * tcp_send_flag() - Send segment with flags to tap (no payload)
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags: if not set, send segment only if ACK is due
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
static int tcp_send_flag(struct ctx *c, struct tcp_tap_conn *conn, int flags)
{
	uint32_t prev_ack_to_tap = conn->seq_ack_to_tap;
	uint32_t prev_wnd_to_tap = conn->wnd_to_tap;
	struct tcp4_l2_flags_buf_t *b4 = NULL;
	struct tcp6_l2_flags_buf_t *b6 = NULL;
	struct tcp_info tinfo = { 0 };
	socklen_t sl = sizeof(tinfo);
	int s = conn->sock;
	size_t optlen = 0;
	struct iovec *iov;
	struct tcphdr *th;
	char *data;
	void *p;

	if (SEQ_GE(conn->seq_ack_to_tap, conn->seq_from_tap) &&
	    !flags && conn->wnd_to_tap)
		return 0;

	if (getsockopt(s, SOL_TCP, TCP_INFO, &tinfo, &sl)) {
		conn_event(c, conn, CLOSED);
		return -ECONNRESET;
	}

#ifdef HAS_SND_WND
	if (!c->tcp.kernel_snd_wnd && tinfo.tcpi_snd_wnd)
		c->tcp.kernel_snd_wnd = 1;
#endif

	if (!(conn->flags & LOCAL))
		tcp_rtt_dst_check(conn, &tinfo);

	if (!tcp_update_seqack_wnd(c, conn, flags, &tinfo) && !flags)
		return 0;

	if (CONN_V4(conn)) {
		iov = tcp4_l2_flags_iov    + tcp4_l2_flags_buf_used;
		p = b4 = tcp4_l2_flags_buf + tcp4_l2_flags_buf_used++;
		th = &b4->th;

		/* gcc 11.2 would complain on data = (char *)(th + 1); */
		data = b4->opts;
	} else {
		iov = tcp6_l2_flags_iov    + tcp6_l2_flags_buf_used;
		p = b6 = tcp6_l2_flags_buf + tcp6_l2_flags_buf_used++;
		th = &b6->th;
		data = b6->opts;
	}

	if (flags & SYN) {
		int mss;

		/* Options: MSS, NOP and window scale (8 bytes) */
		optlen = OPT_MSS_LEN + 1 + OPT_WS_LEN;

		*data++ = OPT_MSS;
		*data++ = OPT_MSS_LEN;

		if (c->mtu == -1) {
			mss = tinfo.tcpi_snd_mss;
		} else {
			mss = c->mtu - sizeof(struct tcphdr);
			if (CONN_V4(conn))
				mss -= sizeof(struct iphdr);
			else
				mss -= sizeof(struct ipv6hdr);

			if (c->low_wmem &&
			    !(conn->flags & LOCAL) && !tcp_rtt_dst_low(conn))
				mss = MIN(mss, PAGE_SIZE);
			else if (mss > PAGE_SIZE)
				mss = ROUND_DOWN(mss, PAGE_SIZE);
		}
		*(uint16_t *)data = htons(MIN(USHRT_MAX, mss));

		data += OPT_MSS_LEN - 2;
		th->doff += OPT_MSS_LEN / 4;

		conn->ws_to_tap = MIN(MAX_WS, tinfo.tcpi_snd_wscale);

		*data++ = OPT_NOP;
		*data++ = OPT_WS;
		*data++ = OPT_WS_LEN;
		*data++ = conn->ws_to_tap;

		th->ack = !!(flags & ACK);
	} else {
		th->ack = !!(flags & (ACK | DUP_ACK)) ||
			  conn->seq_ack_to_tap != prev_ack_to_tap ||
			  !prev_wnd_to_tap;
	}

	th->doff = (sizeof(*th) + optlen) / 4;

	th->rst = !!(flags & RST);
	th->syn = !!(flags & SYN);
	th->fin = !!(flags & FIN);

	iov->iov_len = tcp_l2_buf_fill_headers(c, conn, p, optlen,
					       NULL, conn->seq_to_tap);

	if (th->ack) {
		if (SEQ_GE(conn->seq_ack_to_tap, conn->seq_from_tap))
			conn_flag(c, conn, ~ACK_TO_TAP_DUE);
		else
			conn_flag(c, conn, ACK_TO_TAP_DUE);
	}

	if (th->fin)
		conn_flag(c, conn, ACK_FROM_TAP_DUE);

	/* RFC 793, 3.1: "[...] and the first data octet is ISN+1." */
	if (th->fin || th->syn)
		conn->seq_to_tap++;

	if (CONN_V4(conn)) {
		if (flags & DUP_ACK) {
			memcpy(b4 + 1, b4, sizeof(*b4));
			(iov + 1)->iov_len = iov->iov_len;
			tcp4_l2_flags_buf_used++;
		}

		if (tcp4_l2_flags_buf_used > ARRAY_SIZE(tcp4_l2_flags_buf) - 2)
			tcp_l2_flags_buf_flush(c);
	} else {
		if (flags & DUP_ACK) {
			memcpy(b6 + 1, b6, sizeof(*b6));
			(iov + 1)->iov_len = iov->iov_len;
			tcp6_l2_flags_buf_used++;
		}

		if (tcp6_l2_flags_buf_used > ARRAY_SIZE(tcp6_l2_flags_buf) - 2)
			tcp_l2_flags_buf_flush(c);
	}

	return 0;
}

/**
 * tcp_rst_do() - Reset a tap connection: send RST segment to tap, close socket
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_rst_do(struct ctx *c, struct tcp_tap_conn *conn)
{
	if (conn->events == CLOSED)
		return;

	if (!tcp_send_flag(c, conn, RST))
		conn_event(c, conn, CLOSED);
}

/**
 * tcp_get_tap_ws() - Get Window Scaling option for connection from tap/guest
 * @conn:	Connection pointer
 * @opts:	Pointer to start of TCP options
 * @optlen:	Bytes in options: caller MUST ensure available length
 */
static void tcp_get_tap_ws(struct tcp_tap_conn *conn,
			   const char *opts, size_t optlen)
{
	int ws = tcp_opt_get(opts, optlen, OPT_WS, NULL, NULL);

	if (ws >= 0 && ws <= TCP_WS_MAX)
		conn->ws_from_tap = ws;
	else
		conn->ws_from_tap = 0;
}

/**
 * tcp_clamp_window() - Set new window for connection, clamp on socket
 * @c:		Execution context
 * @conn:	Connection pointer
 * @window:	Window value, host order, unscaled
 */
static void tcp_clamp_window(const struct ctx *c, struct tcp_tap_conn *conn,
			     unsigned wnd)
{
	uint32_t prev_scaled = conn->wnd_from_tap << conn->ws_from_tap;
	int s = conn->sock;

	wnd <<= conn->ws_from_tap;
	wnd = MIN(MAX_WINDOW, wnd);

	if (conn->flags & WND_CLAMPED) {
		if (prev_scaled == wnd)
			return;

		/* Discard +/- 1% updates to spare some syscalls. */
		/* TODO: cppcheck, starting from commit b4d455df487c ("Fix
		 * 11349: FP negativeIndex for clamped array index (#4627)"),
		 * reports wnd > prev_scaled as always being true, see also:
		 *
		 *	https://github.com/danmar/cppcheck/pull/4627
		 *
		 * drop this suppression once that's resolved.
		 */
		/* cppcheck-suppress [knownConditionTrueFalse, unmatchedSuppression] */
		if ((wnd > prev_scaled && wnd * 99 / 100 < prev_scaled) ||
		    (wnd < prev_scaled && wnd * 101 / 100 > prev_scaled))
			return;
	}

	conn->wnd_from_tap = MIN(wnd >> conn->ws_from_tap, USHRT_MAX);
	if (setsockopt(s, SOL_TCP, TCP_WINDOW_CLAMP, &wnd, sizeof(wnd)))
		trace("TCP: failed to set TCP_WINDOW_CLAMP on socket %i", s);

	conn_flag(c, conn, WND_CLAMPED);
}

/**
 * tcp_seq_init() - Calculate initial sequence number according to RFC 6528
 * @c:		Execution context
 * @conn:	TCP connection, with addr, sock_port and tap_port populated
 * @now:	Current timestamp
 */
static void tcp_seq_init(const struct ctx *c, struct tcp_tap_conn *conn,
			 const struct timespec *now)
{
	union inany_addr aany;
	struct {
		union inany_addr src;
		in_port_t srcport;
		union inany_addr dst;
		in_port_t dstport;
	} __attribute__((__packed__)) in = {
		.src = conn->addr,
		.srcport = conn->tap_port,
		.dstport = conn->sock_port,
	};
	uint32_t ns, seq = 0;

	if (CONN_V4(conn))
		inany_from_af(&aany, AF_INET, &c->ip4.addr);
	else
		inany_from_af(&aany, AF_INET6, &c->ip6.addr);
	in.dst = aany;

	seq = siphash_36b((uint8_t *)&in, c->tcp.hash_secret);

	/* 32ns ticks, overflows 32 bits every 137s */
	ns = (now->tv_sec * 1000000000 + now->tv_nsec) >> 5;

	conn->seq_to_tap = seq + ns;
}

/**
 * tcp_conn_pool_sock() - Get socket for new connection from pre-opened pool
 * @pool:	Pool of pre-opened sockets
 *
 * Return: socket number if available, negative code if pool is empty
 */
int tcp_conn_pool_sock(int pool[])
{
	int s = -1, i;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++) {
		SWAP(s, pool[i]);
		if (s >= 0)
			return s;
	}
	return -1;
}

/**
 * tcp_conn_new_sock() - Open and prepare new socket for connection
 * @c:		Execution context
 * @af:		Address family
 *
 * Return: socket number on success, negative code if socket creation failed
 */
int tcp_conn_new_sock(const struct ctx *c, sa_family_t af)
{
	int s;

	s = socket(af, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);

	if (s > SOCKET_MAX) {
		close(s);
		return -EIO;
	}

	if (s < 0)
		return -errno;

	tcp_sock_set_bufsize(c, s);

	return s;
}

/**
 * tcp_conn_tap_mss() - Get MSS value advertised by tap/guest
 * @conn:	Connection pointer
 * @opts:	Pointer to start of TCP options
 * @optlen:	Bytes in options: caller MUST ensure available length
 *
 * Return: clamped MSS value
 */
static uint16_t tcp_conn_tap_mss(const struct tcp_tap_conn *conn,
				 const char *opts, size_t optlen)
{
	unsigned int mss;
	int ret;

	if ((ret = tcp_opt_get(opts, optlen, OPT_MSS, NULL, NULL)) < 0)
		mss = MSS_DEFAULT;
	else
		mss = ret;

	if (CONN_V4(conn))
		mss = MIN(MSS4, mss);
	else
		mss = MIN(MSS6, mss);

	return MIN(mss, USHRT_MAX);
}

/**
 * tcp_bind_outbound() - Bind socket to outbound address and interface if given
 * @c:		Execution context
 * @s:		Outbound TCP socket
 * @af:		Address family
 */
static void tcp_bind_outbound(const struct ctx *c, int s, sa_family_t af)
{
	if (af == AF_INET) {
		if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out)) {
			struct sockaddr_in addr4 = {
				.sin_family = AF_INET,
				.sin_port = 0,
				.sin_addr = c->ip4.addr_out,
			};

			if (bind(s, (struct sockaddr *)&addr4, sizeof(addr4))) {
				debug("Can't bind IPv4 TCP socket address: %s",
				      strerror(errno));
			}
		}

		if (*c->ip4.ifname_out) {
			if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
				       c->ip4.ifname_out,
				       strlen(c->ip4.ifname_out))) {
				debug("Can't bind IPv4 TCP socket to interface:"
				      " %s", strerror(errno));
			}
		}
	} else if (af == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)) {
			struct sockaddr_in6 addr6 = {
				.sin6_family = AF_INET6,
				.sin6_port = 0,
				.sin6_addr = c->ip6.addr_out,
			};

			if (bind(s, (struct sockaddr *)&addr6, sizeof(addr6))) {
				debug("Can't bind IPv6 TCP socket address: %s",
				      strerror(errno));
			}
		}

		if (*c->ip6.ifname_out) {
			if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
				       c->ip6.ifname_out,
				       strlen(c->ip6.ifname_out))) {
				debug("Can't bind IPv6 TCP socket to interface:"
				      " %s", strerror(errno));
			}
		}
	}
}

/**
 * tcp_conn_from_tap() - Handle connection request (SYN segment) from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to in_addr or in6_addr
 * @th:		TCP header from tap: caller MUST ensure it's there
 * @opts:	Pointer to start of options
 * @optlen:	Bytes in options: caller MUST ensure available length
 * @now:	Current timestamp
 */
static void tcp_conn_from_tap(struct ctx *c, int af, const void *addr,
			      const struct tcphdr *th, const char *opts,
			      size_t optlen, const struct timespec *now)
{
	int *pool = af == AF_INET6 ? init_sock_pool6 : init_sock_pool4;
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_port = th->dest,
		.sin_addr = *(struct in_addr *)addr,
	};
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = th->dest,
		.sin6_addr = *(struct in6_addr *)addr,
	};
	const struct sockaddr *sa;
	struct tcp_tap_conn *conn;
	socklen_t sl;
	int s, mss;

	if (c->tcp.conn_count >= TCP_MAX_CONNS)
		return;

	if ((s = tcp_conn_pool_sock(pool)) < 0)
		if ((s = tcp_conn_new_sock(c, af)) < 0)
			return;

	if (!c->no_map_gw) {
		if (af == AF_INET && IN4_ARE_ADDR_EQUAL(addr, &c->ip4.gw))
			addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (af == AF_INET6 && IN6_ARE_ADDR_EQUAL(addr, &c->ip6.gw))
			addr6.sin6_addr	= in6addr_loopback;
	}

	if (af == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr6.sin6_addr)) {
		struct sockaddr_in6 addr6_ll = {
			.sin6_family = AF_INET6,
			.sin6_addr = c->ip6.addr_ll,
			.sin6_scope_id = c->ifi6,
		};
		if (bind(s, (struct sockaddr *)&addr6_ll, sizeof(addr6_ll))) {
			close(s);
			return;
		}
	}

	conn = CONN(c->tcp.conn_count++);
	conn->c.spliced = false;
	conn->sock = s;
	conn->timer = -1;
	conn_event(c, conn, TAP_SYN_RCVD);

	conn->wnd_to_tap = WINDOW_DEFAULT;

	mss = tcp_conn_tap_mss(conn, opts, optlen);
	if (setsockopt(s, SOL_TCP, TCP_MAXSEG, &mss, sizeof(mss)))
		trace("TCP: failed to set TCP_MAXSEG on socket %i", s);
	MSS_SET(conn, mss);

	tcp_get_tap_ws(conn, opts, optlen);

	/* RFC 7323, 2.2: first value is not scaled. Also, don't clamp yet, to
	 * avoid getting a zero scale just because we set a small window now.
	 */
	if (!(conn->wnd_from_tap = (htons(th->window) >> conn->ws_from_tap)))
		conn->wnd_from_tap = 1;

	inany_from_af(&conn->addr, af, addr);

	if (af == AF_INET) {
		sa = (struct sockaddr *)&addr4;
		sl = sizeof(addr4);
	} else {
		sa = (struct sockaddr *)&addr6;
		sl = sizeof(addr6);
	}

	conn->sock_port = ntohs(th->dest);
	conn->tap_port = ntohs(th->source);

	conn->seq_init_from_tap = ntohl(th->seq);
	conn->seq_from_tap = conn->seq_init_from_tap + 1;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	tcp_seq_init(c, conn, now);
	conn->seq_ack_from_tap = conn->seq_to_tap + 1;

	tcp_hash_insert(c, conn);

	if (!bind(s, sa, sl)) {
		tcp_rst(c, conn);	/* Nobody is listening then */
		return;
	}
	if (errno != EADDRNOTAVAIL && errno != EACCES)
		conn_flag(c, conn, LOCAL);

	if ((af == AF_INET &&  !IN4_IS_ADDR_LOOPBACK(&addr4.sin_addr)) ||
	    (af == AF_INET6 && !IN6_IS_ADDR_LOOPBACK(&addr6.sin6_addr) &&
			       !IN6_IS_ADDR_LINKLOCAL(&addr6.sin6_addr)))
		tcp_bind_outbound(c, s, af);

	if (connect(s, sa, sl)) {
		if (errno != EINPROGRESS) {
			tcp_rst(c, conn);
			return;
		}

		tcp_get_sndbuf(conn);
	} else {
		tcp_get_sndbuf(conn);

		if (tcp_send_flag(c, conn, SYN | ACK))
			return;

		conn_event(c, conn, TAP_SYN_ACK_SENT);
	}

	tcp_epoll_ctl(c, conn);
}

/**
 * tcp_sock_consume() - Consume (discard) data from buffer, update ACK sequence
 * @conn:	Connection pointer
 * @ack_seq:	ACK sequence, host order
 *
 * Return: 0 on success, negative error code from recv() on failure
 */
static int tcp_sock_consume(struct tcp_tap_conn *conn, uint32_t ack_seq)
{
	/* Simply ignore out-of-order ACKs: we already consumed the data we
	 * needed from the buffer, and we won't rewind back to a lower ACK
	 * sequence.
	 */
	if (SEQ_LE(ack_seq, conn->seq_ack_from_tap))
		return 0;

	/* cppcheck-suppress [nullPointer, unmatchedSuppression] */
	if (recv(conn->sock, NULL, ack_seq - conn->seq_ack_from_tap,
		 MSG_DONTWAIT | MSG_TRUNC) < 0)
		return -errno;

	return 0;
}

/**
 * tcp_data_to_tap() - Finalise (queue) highest-numbered scatter-gather buffer
 * @c:		Execution context
 * @conn:	Connection pointer
 * @plen:	Payload length at L4
 * @no_csum:	Don't compute IPv4 checksum, use the one from previous buffer
 * @seq:	Sequence number to be sent
 * @now:	Current timestamp
 */
static void tcp_data_to_tap(struct ctx *c, struct tcp_tap_conn *conn,
			    ssize_t plen, int no_csum, uint32_t seq)
{
	struct iovec *iov;

	if (CONN_V4(conn)) {
		struct tcp4_l2_buf_t *b = &tcp4_l2_buf[tcp4_l2_buf_used];
		uint16_t *check = no_csum ? &(b - 1)->iph.check : NULL;

		iov = tcp4_l2_iov + tcp4_l2_buf_used++;
		iov->iov_len = tcp_l2_buf_fill_headers(c, conn, b, plen,
						       check, seq);
		if (tcp4_l2_buf_used > ARRAY_SIZE(tcp4_l2_buf) - 1)
			tcp_l2_data_buf_flush(c);
	} else if (CONN_V6(conn)) {
		struct tcp6_l2_buf_t *b = &tcp6_l2_buf[tcp6_l2_buf_used];

		iov = tcp6_l2_iov + tcp6_l2_buf_used++;
		iov->iov_len = tcp_l2_buf_fill_headers(c, conn, b, plen,
						       NULL, seq);
		if (tcp6_l2_buf_used > ARRAY_SIZE(tcp6_l2_buf) - 1)
			tcp_l2_data_buf_flush(c);
	}
}

/**
 * tcp_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: negative on connection reset, 0 otherwise
 *
 * #syscalls recvmsg
 */
static int tcp_data_from_sock(struct ctx *c, struct tcp_tap_conn *conn)
{
	uint32_t wnd_scaled = conn->wnd_from_tap << conn->ws_from_tap;
	int fill_bufs, send_bufs = 0, last_len, iov_rem = 0;
	int sendlen, len, plen, v4 = CONN_V4(conn);
	int s = conn->sock, i, ret = 0;
	struct msghdr mh_sock = { 0 };
	uint16_t mss = MSS_GET(conn);
	uint32_t already_sent;
	struct iovec *iov;

	already_sent = conn->seq_to_tap - conn->seq_ack_from_tap;

	if (SEQ_LT(already_sent, 0)) {
		/* RFC 761, section 2.1. */
		trace("TCP: ACK sequence gap: ACK for %u, sent: %u",
		      conn->seq_ack_from_tap, conn->seq_to_tap);
		conn->seq_to_tap = conn->seq_ack_from_tap;
		already_sent = 0;
	}

	if (!wnd_scaled || already_sent >= wnd_scaled) {
		conn_flag(c, conn, STALLED);
		conn_flag(c, conn, ACK_FROM_TAP_DUE);
		return 0;
	}

	/* Set up buffer descriptors we'll fill completely and partially. */
	fill_bufs = DIV_ROUND_UP(wnd_scaled - already_sent, mss);
	if (fill_bufs > TCP_FRAMES) {
		fill_bufs = TCP_FRAMES;
		iov_rem = 0;
	} else {
		iov_rem = (wnd_scaled - already_sent) % mss;
	}

	mh_sock.msg_iov = iov_sock;
	mh_sock.msg_iovlen = fill_bufs + 1;

	iov_sock[0].iov_base = tcp_buf_discard;
	iov_sock[0].iov_len = already_sent;

	if (( v4 && tcp4_l2_buf_used + fill_bufs > ARRAY_SIZE(tcp4_l2_buf)) ||
	    (!v4 && tcp6_l2_buf_used + fill_bufs > ARRAY_SIZE(tcp6_l2_buf))) {
		tcp_l2_data_buf_flush(c);

		/* Silence Coverity CWE-125 false positive */
		tcp4_l2_buf_used = tcp6_l2_buf_used = 0;
	}

	for (i = 0, iov = iov_sock + 1; i < fill_bufs; i++, iov++) {
		if (v4)
			iov->iov_base = &tcp4_l2_buf[tcp4_l2_buf_used + i].data;
		else
			iov->iov_base = &tcp6_l2_buf[tcp6_l2_buf_used + i].data;
		iov->iov_len = mss;
	}
	if (iov_rem)
		iov_sock[fill_bufs].iov_len = iov_rem;

	/* Receive into buffers, don't dequeue until acknowledged by guest. */
	do
		len = recvmsg(s, &mh_sock, MSG_PEEK);
	while (len < 0 && errno == EINTR);

	if (len < 0)
		goto err;

	if (!len) {
		if ((conn->events & (SOCK_FIN_RCVD | TAP_FIN_SENT)) == SOCK_FIN_RCVD) {
			if ((ret = tcp_send_flag(c, conn, FIN | ACK))) {
				tcp_rst(c, conn);
				return ret;
			}

			conn_event(c, conn, TAP_FIN_SENT);
		}

		return 0;
	}

	sendlen = len - already_sent;
	if (sendlen <= 0) {
		conn_flag(c, conn, STALLED);
		return 0;
	}

	conn_flag(c, conn, ~STALLED);

	send_bufs = DIV_ROUND_UP(sendlen, mss);
	last_len = sendlen - (send_bufs - 1) * mss;

	/* Likely, some new data was acked too. */
	tcp_update_seqack_wnd(c, conn, 0, NULL);

	/* Finally, queue to tap */
	plen = mss;
	for (i = 0; i < send_bufs; i++) {
		int no_csum = i && i != send_bufs - 1 && tcp4_l2_buf_used;

		if (i == send_bufs - 1)
			plen = last_len;

		tcp_data_to_tap(c, conn, plen, no_csum, conn->seq_to_tap);
		conn->seq_to_tap += plen;
	}

	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	return 0;

err:
	if (errno != EAGAIN && errno != EWOULDBLOCK) {
		ret = -errno;
		tcp_rst(c, conn);
	}

	return ret;
}

/**
 * tcp_data_from_tap() - tap/guest data for established connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @p:		Pool of TCP packets, with TCP headers
 *
 * #syscalls sendmsg
 */
static void tcp_data_from_tap(struct ctx *c, struct tcp_tap_conn *conn,
			      const struct pool *p)
{
	int i, iov_i, ack = 0, fin = 0, retr = 0, keep = -1, partial_send = 0;
	uint16_t max_ack_seq_wnd = conn->wnd_from_tap;
	uint32_t max_ack_seq = conn->seq_ack_from_tap;
	uint32_t seq_from_tap = conn->seq_from_tap;
	struct msghdr mh = { .msg_iov = tcp_iov };
	size_t len;
	ssize_t n;

	for (i = 0, iov_i = 0; i < (int)p->count; i++) {
		uint32_t seq, seq_offset, ack_seq;
		struct tcphdr *th;
		char *data;
		size_t off;

		if (!packet_get(p, i, 0, 0, &len)) {
			tcp_rst(c, conn);
			return;
		}

		th = packet_get(p, i, 0, sizeof(*th), NULL);
		if (!th) {
			tcp_rst(c, conn);
			return;
		}

		off = th->doff * 4UL;
		if (off < sizeof(*th) || off > len) {
			tcp_rst(c, conn);
			return;
		}

		if (th->rst) {
			conn_event(c, conn, CLOSED);
			return;
		}

		len -= off;
		data = packet_get(p, i, off, len, NULL);
		if (!data)
			continue;

		seq = ntohl(th->seq);
		ack_seq = ntohl(th->ack_seq);

		if (th->ack) {
			ack = 1;

			if (SEQ_GE(ack_seq, conn->seq_ack_from_tap) &&
			    SEQ_GE(ack_seq, max_ack_seq)) {
				/* Fast re-transmit */
				retr = !len && !th->fin &&
				       ack_seq == max_ack_seq &&
				       ntohs(th->window) == max_ack_seq_wnd;

				max_ack_seq_wnd = ntohs(th->window);
				max_ack_seq = ack_seq;
			}
		}

		if (th->fin)
			fin = 1;

		if (!len)
			continue;

		seq_offset = seq_from_tap - seq;
		/* Use data from this buffer only in these two cases:
		 *
		 *      , seq_from_tap           , seq_from_tap
		 * |--------| <-- len            |--------| <-- len
		 * '----' <-- offset             ' <-- offset
		 * ^ seq                         ^ seq
		 *    (offset >= 0, seq + len > seq_from_tap)
		 *
		 * discard in these two cases:
		 *          , seq_from_tap                , seq_from_tap
		 * |--------| <-- len            |--------| <-- len
		 * '--------' <-- offset            '-----| <- offset
		 * ^ seq                            ^ seq
		 *    (offset >= 0, seq + len <= seq_from_tap)
		 *
		 * keep, look for another buffer, then go back, in this case:
		 *      , seq_from_tap
		 *          |--------| <-- len
		 *      '===' <-- offset
		 *          ^ seq
		 *    (offset < 0)
		 */
		if (SEQ_GE(seq_offset, 0) && SEQ_LE(seq + len, seq_from_tap))
			continue;

		if (SEQ_LT(seq_offset, 0)) {
			if (keep == -1)
				keep = i;
			continue;
		}

		tcp_iov[iov_i].iov_base = data + seq_offset;
		tcp_iov[iov_i].iov_len = len - seq_offset;
		seq_from_tap += tcp_iov[iov_i].iov_len;
		iov_i++;

		if (keep == i)
			keep = -1;

		if (keep != -1)
			i = keep - 1;
	}

	tcp_clamp_window(c, conn, max_ack_seq_wnd);

	/* On socket flush failure, pretend there was no ACK, try again later */
	if (ack && !tcp_sock_consume(conn, max_ack_seq))
		tcp_update_seqack_from_tap(c, conn, max_ack_seq);

	if (retr) {
		trace("TCP: fast re-transmit, ACK: %u, previous sequence: %u",
		      max_ack_seq, conn->seq_to_tap);
		conn->seq_ack_from_tap = max_ack_seq;
		conn->seq_to_tap = max_ack_seq;
		tcp_data_from_sock(c, conn);
	}

	if (!iov_i)
		goto out;

	mh.msg_iovlen = iov_i;
eintr:
	n = sendmsg(conn->sock, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0) {
		if (errno == EPIPE) {
			/* Here's the wrap, said the tap.
			 * In my pocket, said the socket.
			 *   Then swiftly looked away and left.
			 */
			conn->seq_from_tap = seq_from_tap;
			tcp_send_flag(c, conn, ACK);
		}

		if (errno == EINTR)
			goto eintr;

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			tcp_send_flag(c, conn, ACK_IF_NEEDED);
			return;
		}
		tcp_rst(c, conn);
		return;
	}

	if (n < (int)(seq_from_tap - conn->seq_from_tap)) {
		partial_send = 1;
		conn->seq_from_tap += n;
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
	} else {
		conn->seq_from_tap += n;
	}

out:
	if (keep != -1) {
		/* We use an 8-bit approximation here: the associated risk is
		 * that we skip a duplicate ACK on 8-bit sequence number
		 * collision. Fast retransmit is a SHOULD in RFC 5681, 3.2.
		 */
		if (conn->seq_dup_ack_approx != (conn->seq_from_tap & 0xff)) {
			conn->seq_dup_ack_approx = conn->seq_from_tap & 0xff;
			tcp_send_flag(c, conn, DUP_ACK);
		}
		return;
	}

	if (ack && conn->events & TAP_FIN_SENT &&
	    conn->seq_ack_from_tap == conn->seq_to_tap)
		conn_event(c, conn, TAP_FIN_ACKED);

	if (fin && !partial_send) {
		conn->seq_from_tap++;

		conn_event(c, conn, TAP_FIN_RCVD);
	} else {
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
	}
}

/**
 * tcp_conn_from_sock_finish() - Complete connection setup after connect()
 * @c:		Execution context
 * @conn:	Connection pointer
 * @th:		TCP header of SYN, ACK segment: caller MUST ensure it's there
 * @opts:	Pointer to start of options
 * @optlen:	Bytes in options: caller MUST ensure available length
 */
static void tcp_conn_from_sock_finish(struct ctx *c, struct tcp_tap_conn *conn,
				      const struct tcphdr *th,
				      const char *opts, size_t optlen)
{
	tcp_clamp_window(c, conn, ntohs(th->window));
	tcp_get_tap_ws(conn, opts, optlen);

	/* First value is not scaled */
	if (!(conn->wnd_from_tap >>= conn->ws_from_tap))
		conn->wnd_from_tap = 1;

	MSS_SET(conn, tcp_conn_tap_mss(conn, opts, optlen));

	conn->seq_init_from_tap = ntohl(th->seq) + 1;
	conn->seq_from_tap = conn->seq_init_from_tap;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	conn_event(c, conn, ESTABLISHED);

	/* The client might have sent data already, which we didn't
	 * dequeue waiting for SYN,ACK from tap -- check now.
	 */
	tcp_data_from_sock(c, conn);
	tcp_send_flag(c, conn, ACK_IF_NEEDED);
}

/**
 * tcp_tap_handler() - Handle packets from tap and state transitions
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Destination address
 * @p:		Pool of TCP packets, with TCP headers
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 */
int tcp_tap_handler(struct ctx *c, int af, const void *addr,
		    const struct pool *p, const struct timespec *now)
{
	struct tcp_tap_conn *conn;
	size_t optlen, len;
	struct tcphdr *th;
	int ack_due = 0;
	char *opts;

	if (!packet_get(p, 0, 0, 0, &len))
		return 1;

	th = packet_get(p, 0, 0, sizeof(*th), NULL);
	if (!th)
		return 1;

	optlen = th->doff * 4UL - sizeof(*th);
	/* Static checkers might fail to see this: */
	optlen = MIN(optlen, ((1UL << 4) /* from doff width */ - 6) * 4UL);
	opts = packet_get(p, 0, sizeof(*th), optlen, NULL);

	conn = tcp_hash_lookup(c, af, addr, htons(th->source), htons(th->dest));

	/* New connection from tap */
	if (!conn) {
		if (opts && th->syn && !th->ack)
			tcp_conn_from_tap(c, af, addr, th, opts, optlen, now);
		return 1;
	}

	trace("TCP: packet length %lu from tap for index %lu", len, CONN_IDX(conn));

	if (th->rst) {
		conn_event(c, conn, CLOSED);
		return p->count;
	}

	if (th->ack && !(conn->events & ESTABLISHED))
		tcp_update_seqack_from_tap(c, conn, ntohl(th->ack_seq));

	conn_flag(c, conn, ~STALLED);

	/* Establishing connection from socket */
	if (conn->events & SOCK_ACCEPTED) {
		if (th->syn && th->ack && !th->fin)
			tcp_conn_from_sock_finish(c, conn, th, opts, optlen);
		else
			tcp_rst(c, conn);

		return 1;
	}

	/* Establishing connection from tap */
	if (conn->events & TAP_SYN_RCVD) {
		if (!(conn->events & TAP_SYN_ACK_SENT)) {
			tcp_rst(c, conn);
			return p->count;
		}

		conn_event(c, conn, ESTABLISHED);

		if (th->fin) {
			conn->seq_from_tap++;

			shutdown(conn->sock, SHUT_WR);
			tcp_send_flag(c, conn, ACK);
			conn_event(c, conn, SOCK_FIN_SENT);

			return p->count;
		}

		if (!th->ack) {
			tcp_rst(c, conn);
			return p->count;
		}

		tcp_clamp_window(c, conn, ntohs(th->window));

		tcp_data_from_sock(c, conn);

		if (p->count == 1)
			return 1;
	}

	/* Established connections not accepting data from tap */
	if (conn->events & TAP_FIN_RCVD) {
		tcp_update_seqack_from_tap(c, conn, ntohl(th->ack_seq));

		if (conn->events & SOCK_FIN_RCVD &&
		    conn->seq_ack_from_tap == conn->seq_to_tap)
			conn_event(c, conn, CLOSED);

		return 1;
	}

	/* Established connections accepting data from tap */
	tcp_data_from_tap(c, conn, p);
	if (conn->seq_ack_to_tap != conn->seq_from_tap)
		ack_due = 1;

	if ((conn->events & TAP_FIN_RCVD) && !(conn->events & SOCK_FIN_SENT)) {
		shutdown(conn->sock, SHUT_WR);
		conn_event(c, conn, SOCK_FIN_SENT);
		tcp_send_flag(c, conn, ACK);
		ack_due = 0;
	}

	if (ack_due)
		conn_flag(c, conn, ACK_TO_TAP_DUE);

	return p->count;
}

/**
 * tcp_connect_finish() - Handle completion of connect() from EPOLLOUT event
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_connect_finish(struct ctx *c, struct tcp_tap_conn *conn)
{
	socklen_t sl;
	int so;

	sl = sizeof(so);
	if (getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, &so, &sl) || so) {
		tcp_rst(c, conn);
		return;
	}

	if (tcp_send_flag(c, conn, SYN | ACK))
		return;

	conn_event(c, conn, TAP_SYN_ACK_SENT);
	conn_flag(c, conn, ACK_FROM_TAP_DUE);
}

/**
 * tcp_snat_inbound() - Translate source address for inbound data if needed
 * @c:		Execution context
 * @addr:	Source address of inbound packet/connection
 */
static void tcp_snat_inbound(const struct ctx *c, union inany_addr *addr)
{
	struct in_addr *addr4 = inany_v4(addr);

	if (addr4) {
		if (IN4_IS_ADDR_LOOPBACK(addr4) ||
		    IN4_IS_ADDR_UNSPECIFIED(addr4) ||
		    IN4_ARE_ADDR_EQUAL(addr4, &c->ip4.addr_seen))
			*addr4 = c->ip4.gw;
	} else {
		struct in6_addr *addr6 = &addr->a6;

		if (IN6_IS_ADDR_LOOPBACK(addr6) ||
		    IN6_ARE_ADDR_EQUAL(addr6, &c->ip6.addr_seen) ||
		    IN6_ARE_ADDR_EQUAL(addr6, &c->ip6.addr)) {
			if (IN6_IS_ADDR_LINKLOCAL(&c->ip6.gw))
				*addr6 = c->ip6.gw;
			else
				*addr6 = c->ip6.addr_ll;
		}
	}
}

/**
 * tcp_tap_conn_from_sock() - Initialize state for non-spliced connection
 * @c:		Execution context
 * @ref:	epoll reference of listening socket
 * @conn:	connection structure to initialize
 * @s:		Accepted socket
 * @sa:		Peer socket address (from accept())
 * @now:	Current timestamp
 */
static void tcp_tap_conn_from_sock(struct ctx *c, union epoll_ref ref,
				   struct tcp_tap_conn *conn, int s,
				   struct sockaddr *sa,
				   const struct timespec *now)
{
	conn->c.spliced = false;
	conn->sock = s;
	conn->timer = -1;
	conn->ws_to_tap = conn->ws_from_tap = 0;
	conn_event(c, conn, SOCK_ACCEPTED);

	inany_from_sockaddr(&conn->addr, &conn->sock_port, sa);
	conn->tap_port = ref.r.p.tcp.tcp.index;

	tcp_snat_inbound(c, &conn->addr);

	tcp_seq_init(c, conn, now);
	tcp_hash_insert(c, conn);

	conn->seq_ack_from_tap = conn->seq_to_tap + 1;

	conn->wnd_from_tap = WINDOW_DEFAULT;

	tcp_send_flag(c, conn, SYN);
	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	tcp_get_sndbuf(conn);
}

/**
 * tcp_conn_from_sock() - Handle new connection request from listening socket
 * @c:		Execution context
 * @ref:	epoll reference of listening socket
 * @now:	Current timestamp
 */
static void tcp_conn_from_sock(struct ctx *c, union epoll_ref ref,
			       const struct timespec *now)
{
	struct sockaddr_storage sa;
	union tcp_conn *conn;
	socklen_t sl;
	int s;

	ASSERT(ref.r.p.tcp.tcp.listen);

	if (c->tcp.conn_count >= TCP_MAX_CONNS)
		return;

	sl = sizeof(sa);
	/* FIXME: Workaround clang-tidy not realizing that accept4()
	 * writes the socket address.  See
	 * https://github.com/llvm/llvm-project/issues/58992
	 */
	memset(&sa, 0, sizeof(struct sockaddr_in6));
	s = accept4(ref.r.s, (struct sockaddr *)&sa, &sl, SOCK_NONBLOCK);
	if (s < 0)
		return;

	conn = tc + c->tcp.conn_count++;

	if (c->mode == MODE_PASTA &&
	    tcp_splice_conn_from_sock(c, ref, &conn->splice,
				      s, (struct sockaddr *)&sa))
		return;

	tcp_tap_conn_from_sock(c, ref, &conn->tap, s,
			       (struct sockaddr *)&sa, now);
}

/**
 * tcp_timer_handler() - timerfd events: close, send ACK, retransmit, or reset
 * @c:		Execution context
 * @ref:	epoll reference of timer (not connection)
 *
 * #syscalls timerfd_gettime
 */
static void tcp_timer_handler(struct ctx *c, union epoll_ref ref)
{
	struct tcp_tap_conn *conn = conn_at_idx(ref.r.p.tcp.tcp.index);
	struct itimerspec check_armed = { { 0 }, { 0 } };

	if (!conn)
		return;

	/* We don't reset timers on ~ACK_FROM_TAP_DUE, ~ACK_TO_TAP_DUE. If the
	 * timer is currently armed, this event came from a previous setting,
	 * and we just set the timer to a new point in the future: discard it.
	 */
	timerfd_gettime(conn->timer, &check_armed);
	if (check_armed.it_value.tv_sec || check_armed.it_value.tv_nsec)
		return;

	if (conn->flags & ACK_TO_TAP_DUE) {
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
		tcp_timer_ctl(c, conn);
	} else if (conn->flags & ACK_FROM_TAP_DUE) {
		if (!(conn->events & ESTABLISHED)) {
			debug("TCP: index %li, handshake timeout", CONN_IDX(conn));
			tcp_rst(c, conn);
		} else if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED)) {
			debug("TCP: index %li, FIN timeout", CONN_IDX(conn));
			tcp_rst(c, conn);
		} else if (conn->retrans == TCP_MAX_RETRANS) {
			debug("TCP: index %li, retransmissions count exceeded",
			      CONN_IDX(conn));
			tcp_rst(c, conn);
		} else {
			debug("TCP: index %li, ACK timeout, retry", CONN_IDX(conn));
			conn->retrans++;
			conn->seq_to_tap = conn->seq_ack_from_tap;
			tcp_data_from_sock(c, conn);
			tcp_timer_ctl(c, conn);
		}
	} else {
		struct itimerspec new = { { 0 }, { ACT_TIMEOUT, 0 } };
		struct itimerspec old = { { 0 }, { 0 } };

		/* Activity timeout: if it was already set, reset the
		 * connection, otherwise, it was a left-over from ACK_TO_TAP_DUE
		 * or ACK_FROM_TAP_DUE, so just set the long timeout in that
		 * case. This avoids having to preemptively reset the timer on
		 * ~ACK_TO_TAP_DUE or ~ACK_FROM_TAP_DUE.
		 */
		timerfd_settime(conn->timer, 0, &new, &old);
		if (old.it_value.tv_sec == ACT_TIMEOUT) {
			debug("TCP: index %li, activity timeout", CONN_IDX(conn));
			tcp_rst(c, conn);
		}
	}
}

/**
 * tcp_tap_sock_handler() - Handle new data from non-spliced socket
 * @c:		Execution context
 * @conn:	Connection state
 * @events:	epoll events bitmap
 */
static void tcp_tap_sock_handler(struct ctx *c, struct tcp_tap_conn *conn,
				 uint32_t events)
{
	if (conn->events == CLOSED)
		return;

	if (events & EPOLLERR) {
		tcp_rst(c, conn);
		return;
	}

	if ((conn->events & TAP_FIN_SENT) && (events & EPOLLHUP)) {
		conn_event(c, conn, CLOSED);
		return;
	}

	if (conn->events & ESTABLISHED) {
		if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED))
			conn_event(c, conn, CLOSED);

		if (events & (EPOLLRDHUP | EPOLLHUP))
			conn_event(c, conn, SOCK_FIN_RCVD);

		if (events & EPOLLIN)
			tcp_data_from_sock(c, conn);

		if (events & EPOLLOUT)
			tcp_update_seqack_wnd(c, conn, 0, NULL);

		return;
	}

	/* EPOLLHUP during handshake: reset */
	if (events & EPOLLHUP) {
		tcp_rst(c, conn);
		return;
	}

	/* Data during handshake tap-side: check later */
	if (conn->events & SOCK_ACCEPTED)
		return;

	if (conn->events == TAP_SYN_RCVD) {
		if (events & EPOLLOUT)
			tcp_connect_finish(c, conn);
		/* Data? Check later */
	}
}

/**
 * tcp_sock_handler() - Handle new data from socket, or timerfd event
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
void tcp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      const struct timespec *now)
{
	union tcp_conn *conn;

	if (ref.r.p.tcp.tcp.timer) {
		tcp_timer_handler(c, ref);
		return;
	}

	if (ref.r.p.tcp.tcp.listen) {
		tcp_conn_from_sock(c, ref, now);
		return;
	}

	conn = tc + ref.r.p.tcp.tcp.index;

	if (conn->c.spliced)
		tcp_splice_sock_handler(c, &conn->splice, ref.r.s, events);
	else
		tcp_tap_sock_handler(c, &conn->tap, events);
}

/**
 * tcp_sock_init_af() - Initialise listening socket for a given af and port
 * @c:		Execution context
 * @af:		Address family to listen on
 * @port:	Port, host order
 * @addr:	Pointer to address for binding, NULL if not configured
 * @ifname:	Name of interface to bind to, NULL if not configured
 *
 * Return: fd for the new listening socket, negative error code on failure
 */
static int tcp_sock_init_af(const struct ctx *c, int af, in_port_t port,
			    const struct in_addr *addr, const char *ifname)
{
	in_port_t idx = port + c->tcp.fwd_in.delta[port];
	union tcp_epoll_ref tref = { .tcp.listen = 1, .tcp.index = idx };
	int s;

	s = sock_l4(c, af, IPPROTO_TCP, addr, ifname, port, tref.u32);

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		if (af == AF_INET  || af == AF_UNSPEC)
			tcp_sock_init_ext[port][V4] = s < 0 ? -1 : s;
		if (af == AF_INET6 || af == AF_UNSPEC)
			tcp_sock_init_ext[port][V6] = s < 0 ? -1 : s;
	}

	if (s < 0)
		return s;

	tcp_sock_set_bufsize(c, s);
	return s;
}

/**
 * tcp_sock_init() - Create listening sockets for a given host ("inbound") port
 * @c:		Execution context
 * @af:		Address family to select a specific IP version, or AF_UNSPEC
 * @addr:	Pointer to address for binding, NULL if not configured
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 *
 * Return: 0 on (partial) success, negative error code on (complete) failure
 */
int tcp_sock_init(const struct ctx *c, sa_family_t af, const void *addr,
		  const char *ifname, in_port_t port)
{
	int r4 = SOCKET_MAX + 1, r6 = SOCKET_MAX + 1;

	if (af == AF_UNSPEC && c->ifi4 && c->ifi6)
		/* Attempt to get a dual stack socket */
		if (tcp_sock_init_af(c, AF_UNSPEC, port, addr, ifname) >= 0)
			return 0;

	/* Otherwise create a socket per IP version */
	if ((af == AF_INET  || af == AF_UNSPEC) && c->ifi4)
		r4 = tcp_sock_init_af(c, AF_INET, port, addr, ifname);

	if ((af == AF_INET6 || af == AF_UNSPEC) && c->ifi6)
		r6 = tcp_sock_init_af(c, AF_INET6, port, addr, ifname);

	if (IN_INTERVAL(0, SOCKET_MAX, r4) || IN_INTERVAL(0, SOCKET_MAX, r6))
		return 0;

	return r4 < 0 ? r4 : r6;
}

/**
 * tcp_ns_sock_init4() - Init socket to listen for outbound IPv4 connections
 * @c:		Execution context
 * @port:	Port, host order
 */
static void tcp_ns_sock_init4(const struct ctx *c, in_port_t port)
{
	in_port_t idx = port + c->tcp.fwd_out.delta[port];
	union tcp_epoll_ref tref = { .tcp.listen = 1, .tcp.outbound = 1,
				     .tcp.index = idx };
	struct in_addr loopback = { htonl(INADDR_LOOPBACK) };
	int s;

	ASSERT(c->mode == MODE_PASTA);

	s = sock_l4(c, AF_INET, IPPROTO_TCP, &loopback, NULL, port, tref.u32);
	if (s >= 0)
		tcp_sock_set_bufsize(c, s);
	else
		s = -1;

	if (c->tcp.fwd_out.mode == FWD_AUTO)
		tcp_sock_ns[port][V4] = s;
}

/**
 * tcp_ns_sock_init6() - Init socket to listen for outbound IPv6 connections
 * @c:		Execution context
 * @port:	Port, host order
 */
static void tcp_ns_sock_init6(const struct ctx *c, in_port_t port)
{
	in_port_t idx = port + c->tcp.fwd_out.delta[port];
	union tcp_epoll_ref tref = { .tcp.listen = 1, .tcp.outbound = 1,
				     .tcp.index = idx };
	int s;

	ASSERT(c->mode == MODE_PASTA);

	s = sock_l4(c, AF_INET6, IPPROTO_TCP, &in6addr_loopback, NULL, port,
		    tref.u32);
	if (s >= 0)
		tcp_sock_set_bufsize(c, s);
	else
		s = -1;

	if (c->tcp.fwd_out.mode == FWD_AUTO)
		tcp_sock_ns[port][V6] = s;
}

/**
 * tcp_ns_sock_init() - Init socket to listen for spliced outbound connections
 * @c:		Execution context
 * @port:	Port, host order
 */
void tcp_ns_sock_init(const struct ctx *c, in_port_t port)
{
	if (c->ifi4)
		tcp_ns_sock_init4(c, port);
	if (c->ifi6)
		tcp_ns_sock_init6(c, port);
}

/**
 * tcp_ns_socks_init() - Bind sockets in namespace for outbound connections
 * @arg:	Execution context
 *
 * Return: 0
 */
static int tcp_ns_socks_init(void *arg)
{
	struct ctx *c = (struct ctx *)arg;
	unsigned port;

	ns_enter(c);

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bitmap_isset(c->tcp.fwd_out.map, port))
			continue;

		tcp_ns_sock_init(c, port);
	}

	return 0;
}

/**
 * tcp_sock_refill_pool() - Refill one pool of pre-opened sockets
 * @c:		Execution context
 * @pool:	Pool of sockets to refill
 * @af:		Address family to use
 */
void tcp_sock_refill_pool(const struct ctx *c, int pool[], int af)
{
	int i;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++) {
		if (pool[i] >= 0)
			break;

		pool[i] = tcp_conn_new_sock(c, af);
	}
}

/**
 * tcp_sock_refill_init() - Refill pools of pre-opened sockets in init ns
 * @c:		Execution context
 */
static void tcp_sock_refill_init(const struct ctx *c)
{
	if (c->ifi4)
		tcp_sock_refill_pool(c, init_sock_pool4, AF_INET);
	if (c->ifi6)
		tcp_sock_refill_pool(c, init_sock_pool6, AF_INET6);
}

/**
 * tcp_init() - Get initial sequence, hash secret, initialise per-socket data
 * @c:		Execution context
 *
 * Return: 0, doesn't return on failure
 */
int tcp_init(struct ctx *c)
{
	int i;
#ifndef HAS_GETRANDOM
	int dev_random = open("/dev/random", O_RDONLY);
	unsigned int random_read = 0;

	while (dev_random && random_read < sizeof(c->tcp.hash_secret)) {
		int ret = read(dev_random,
			       (uint8_t *)&c->tcp.hash_secret + random_read,
			       sizeof(c->tcp.hash_secret) - random_read);

		if (ret == -1 && errno == EINTR)
			continue;

		if (ret <= 0)
			break;

		random_read += ret;
	}
	if (dev_random >= 0)
		close(dev_random);
	if (random_read < sizeof(c->tcp.hash_secret)) {
#else
	if (getrandom(&c->tcp.hash_secret, sizeof(c->tcp.hash_secret),
		      GRND_RANDOM) < 0) {
#endif /* !HAS_GETRANDOM */
		perror("TCP initial sequence getrandom");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < ARRAY_SIZE(tcp_l2_mh); i++)
		tcp_l2_mh[i] = (struct mmsghdr) { .msg_hdr.msg_iovlen = 1 };

	if (c->ifi4)
		tcp_sock4_iov_init(c);

	if (c->ifi6)
		tcp_sock6_iov_init(c);

	memset(init_sock_pool4,		0xff,	sizeof(init_sock_pool4));
	memset(init_sock_pool6,		0xff,	sizeof(init_sock_pool6));
	memset(tcp_sock_init_ext,	0xff,	sizeof(tcp_sock_init_ext));
	memset(tcp_sock_ns,		0xff,	sizeof(tcp_sock_ns));

	tcp_sock_refill_init(c);

	if (c->mode == MODE_PASTA) {
		tcp_splice_init(c);

		NS_CALL(tcp_ns_socks_init, c);
	}

	return 0;
}

/**
 * struct tcp_port_detect_arg - Arguments for tcp_port_detect()
 * @c:			Execution context
 * @detect_in_ns:	Detect ports bound in namespace, not in init
 */
struct tcp_port_detect_arg {
	struct ctx *c;
	int detect_in_ns;
};

/**
 * tcp_port_detect() - Detect ports bound in namespace or init
 * @arg:		See struct tcp_port_detect_arg
 *
 * Return: 0
 */
static int tcp_port_detect(void *arg)
{
	struct tcp_port_detect_arg *a = (struct tcp_port_detect_arg *)arg;

	if (a->detect_in_ns) {
		ns_enter(a->c);

		get_bound_ports(a->c, 1, IPPROTO_TCP);
	} else {
		get_bound_ports(a->c, 0, IPPROTO_TCP);
	}

	return 0;
}

/**
 * struct tcp_port_rebind_arg - Arguments for tcp_port_rebind()
 * @c:			Execution context
 * @bind_in_ns:		Rebind ports in namespace, not in init
 */
struct tcp_port_rebind_arg {
	struct ctx *c;
	int bind_in_ns;
};

/**
 * tcp_port_rebind() - Rebind ports in namespace or init
 * @arg:		See struct tcp_port_rebind_arg
 *
 * Return: 0
 */
static int tcp_port_rebind(void *arg)
{
	struct tcp_port_rebind_arg *a = (struct tcp_port_rebind_arg *)arg;
	unsigned port;

	if (a->bind_in_ns) {
		ns_enter(a->c);

		for (port = 0; port < NUM_PORTS; port++) {
			if (!bitmap_isset(a->c->tcp.fwd_out.map, port)) {
				if (tcp_sock_ns[port][V4] >= 0) {
					close(tcp_sock_ns[port][V4]);
					tcp_sock_ns[port][V4] = -1;
				}

				if (tcp_sock_ns[port][V6] >= 0) {
					close(tcp_sock_ns[port][V6]);
					tcp_sock_ns[port][V6] = -1;
				}

				continue;
			}

			/* Don't loop back our own ports */
			if (bitmap_isset(a->c->tcp.fwd_in.map, port))
				continue;

			if ((a->c->ifi4 && tcp_sock_ns[port][V4] == -1) ||
			    (a->c->ifi6 && tcp_sock_ns[port][V6] == -1))
				tcp_ns_sock_init(a->c, port);
		}
	} else {
		for (port = 0; port < NUM_PORTS; port++) {
			if (!bitmap_isset(a->c->tcp.fwd_in.map, port)) {
				if (tcp_sock_init_ext[port][V4] >= 0) {
					close(tcp_sock_init_ext[port][V4]);
					tcp_sock_init_ext[port][V4] = -1;
				}

				if (tcp_sock_init_ext[port][V6] >= 0) {
					close(tcp_sock_init_ext[port][V6]);
					tcp_sock_init_ext[port][V6] = -1;
				}
				continue;
			}

			/* Don't loop back our own ports */
			if (bitmap_isset(a->c->tcp.fwd_out.map, port))
				continue;

			if ((a->c->ifi4 && tcp_sock_init_ext[port][V4] == -1) ||
			    (a->c->ifi6 && tcp_sock_init_ext[port][V6] == -1))
				tcp_sock_init(a->c, AF_UNSPEC, NULL, NULL,
					      port);
		}
	}

	return 0;
}

/**
 * tcp_timer() - Periodic tasks: port detection, closed connections, pool refill
 * @c:		Execution context
 * @ts:		Unused
 */
void tcp_timer(struct ctx *c, const struct timespec *ts)
{
	union tcp_conn *conn;

	(void)ts;

	if (c->mode == MODE_PASTA) {
		struct tcp_port_detect_arg detect_arg = { c, 0 };
		struct tcp_port_rebind_arg rebind_arg = { c, 0 };

		if (c->tcp.fwd_out.mode == FWD_AUTO) {
			detect_arg.detect_in_ns = 0;
			tcp_port_detect(&detect_arg);
			rebind_arg.bind_in_ns = 1;
			NS_CALL(tcp_port_rebind, &rebind_arg);
		}

		if (c->tcp.fwd_in.mode == FWD_AUTO) {
			detect_arg.detect_in_ns = 1;
			NS_CALL(tcp_port_detect, &detect_arg);
			rebind_arg.bind_in_ns = 0;
			tcp_port_rebind(&rebind_arg);
		}
	}

	for (conn = tc + c->tcp.conn_count - 1; conn >= tc; conn--) {
		if (conn->c.spliced) {
			tcp_splice_timer(c, conn);
		} else {
			if (conn->tap.events == CLOSED)
				tcp_conn_destroy(c, conn);
		}
	}

	tcp_sock_refill_init(c);
	if (c->mode == MODE_PASTA)
		tcp_splice_refill(c);
}

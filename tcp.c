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
 * Connections are tracked by the @tc array of struct tcp_conn, containing
 * addresses, ports, TCP states and parameters. This is statically allocated and
 * indexed by an arbitrary connection number. The array is compacted whenever a
 * connection is closed, by remapping the highest connection index in use to the
 * one freed up.
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
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
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
#include <unistd.h>
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

#define TCP_FRAMES_MEM			128
#define TCP_FRAMES							\
	(c->mode == MODE_PASST ? TCP_FRAMES_MEM : 1)

#define TCP_FILE_PRESSURE		30	/* % of c->nofile */
#define TCP_CONN_PRESSURE		30	/* % of c->tcp.conn_count */

#define TCP_HASH_BUCKET_BITS		(TCP_CONN_INDEX_BITS + 1)
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
	uint32_t vnet_len;
	struct ethhdr eh;
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
	uint32_t vnet_len;
	struct ethhdr eh;
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

#define ACK_INTERVAL			50		/* ms */
#define SYN_TIMEOUT			10		/* s */
#define ACK_TIMEOUT			2
#define FIN_TIMEOUT			60
#define ACT_TIMEOUT			7200

#define TCP_SOCK_POOL_TSH		16 /* Refill in ns if > x used */

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

/**
 * struct tcp_conn - Descriptor for a TCP connection (not spliced)
 * @next_index:		Connection index of next item in hash chain, -1 for none
 * @tap_mss:		MSS advertised by tap/guest, rounded to 2 ^ TCP_MSS_BITS
 * @sock:		Socket descriptor number
 * @events:		Connection events, implying connection states
 * @timer:		timerfd descriptor for timeout events
 * @flags:		Connection flags representing internal attributes
 * @hash_bucket:	Bucket index in connection lookup hash table
 * @retrans:		Number of retransmissions occurred due to ACK_TIMEOUT
 * @ws_from_tap:	Window scaling factor advertised from tap/guest
 * @ws_to_tap:		Window scaling factor advertised to tap/guest
 * @sndbuf:		Sending buffer in kernel, rounded to 2 ^ SNDBUF_BITS
 * @seq_dup_ack_approx:	Last duplicate ACK number sent to tap
 * @a.a6:		IPv6 remote address, can be IPv4-mapped
 * @a.a4.zero:		Zero prefix for IPv4-mapped, see RFC 6890, Table 20
 * @a.a4.one:		Ones prefix for IPv4-mapped
 * @a.a4.a:		IPv4 address
 * @tap_port:		Guest-facing tap port
 * @sock_port:		Remote, socket-facing port
 * @wnd_from_tap:	Last window size from tap, unscaled (as received)
 * @wnd_to_tap:		Sending window advertised to tap, unscaled (as sent)
 * @seq_to_tap:		Next sequence for packets to tap
 * @seq_ack_from_tap:	Last ACK number received from tap
 * @seq_from_tap:	Next sequence for packets from tap (not actually sent)
 * @seq_ack_to_tap:	Last ACK number sent to tap
 * @seq_init_from_tap:	Initial sequence number from tap
 */
struct tcp_conn {
	int	 	next_index	:TCP_CONN_INDEX_BITS + 2;

#define TCP_RETRANS_BITS		3
	unsigned int	retrans		:TCP_RETRANS_BITS;
#define TCP_MAX_RETRANS			((1U << TCP_RETRANS_BITS) - 1)

#define TCP_WS_BITS			4	/* RFC 7323 */
#define TCP_WS_MAX			14
	unsigned int	ws_from_tap	:TCP_WS_BITS;
	unsigned int	ws_to_tap	:TCP_WS_BITS;


	int		sock		:SOCKET_REF_BITS;

	uint8_t		events;
#define CLOSED			0
#define SOCK_ACCEPTED		BIT(0)	/* implies SYN sent to tap */
#define TAP_SYN_RCVD		BIT(1)	/* implies socket connecting */
#define  TAP_SYN_ACK_SENT	BIT( 3)	/* implies socket connected */
#define ESTABLISHED		BIT(2)
#define  SOCK_FIN_RCVD		BIT( 3)
#define  SOCK_FIN_SENT		BIT( 4)
#define  TAP_FIN_RCVD		BIT( 5)
#define  TAP_FIN_SENT		BIT( 6)
#define  TAP_FIN_ACKED		BIT( 7)

#define	CONN_STATE_BITS		/* Setting these clears other flags */	\
	(SOCK_ACCEPTED | TAP_SYN_RCVD | ESTABLISHED)


	int		timer		:SOCKET_REF_BITS;

	uint8_t		flags;
#define STALLED			BIT(0)
#define LOCAL			BIT(1)
#define WND_CLAMPED		BIT(2)
#define IN_EPOLL		BIT(3)
#define ACTIVE_CLOSE		BIT(4)
#define ACK_TO_TAP_DUE		BIT(5)
#define ACK_FROM_TAP_DUE	BIT(6)


	unsigned int	hash_bucket	:TCP_HASH_BUCKET_BITS;

#define TCP_MSS_BITS			14
	unsigned int	tap_mss		:TCP_MSS_BITS;
#define MSS_SET(conn, mss)	(conn->tap_mss = (mss >> (16 - TCP_MSS_BITS)))
#define MSS_GET(conn)		(conn->tap_mss << (16 - TCP_MSS_BITS))


#define SNDBUF_BITS		24
	unsigned int	sndbuf		:SNDBUF_BITS;
#define SNDBUF_SET(conn, bytes)	(conn->sndbuf = ((bytes) >> (32 - SNDBUF_BITS)))
#define SNDBUF_GET(conn)	(conn->sndbuf << (32 - SNDBUF_BITS))

	uint8_t		seq_dup_ack_approx;


	union {
		struct in6_addr a6;
		struct {
			uint8_t zero[10];
			uint8_t one[2];
			struct in_addr a;
		} a4;
	} a;
#define CONN_V4(conn)		IN6_IS_ADDR_V4MAPPED(&conn->a.a6)
#define CONN_V6(conn)		(!CONN_V4(conn))

	in_port_t	tap_port;
	in_port_t	sock_port;

	uint16_t	wnd_from_tap;
	uint16_t	wnd_to_tap;

	uint32_t	seq_to_tap;
	uint32_t	seq_ack_from_tap;
	uint32_t	seq_from_tap;
	uint32_t	seq_ack_to_tap;
	uint32_t	seq_init_from_tap;
};

#define CONN_IS_CLOSING(conn)						\
	((conn->events & ESTABLISHED) &&				\
	 (conn->events & (SOCK_FIN_RCVD | TAP_FIN_RCVD)))
#define CONN_HAS(conn, set)	((conn->events & (set)) == (set))

#define CONN(index)		(tc + (index))

/* We probably don't want to use gcc statement expressions (for portability), so
 * use this only after well-defined sequence points (no pre-/post-increments).
 */
#define CONN_OR_NULL(index)						\
	(((int)(index) >= 0 && (index) < TCP_MAX_CONNS) ? (tc + (index)) : NULL)

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
	"STALLED", "LOCAL", "WND_CLAMPED", "IN_EPOLL", "ACTIVE_CLOSE",
	"ACK_TO_TAP_DUE", "ACK_FROM_TAP_DUE",
};

/* Port re-mappings as delta, indexed by original destination port */
static in_port_t		tcp_port_delta_to_tap	[USHRT_MAX];
static in_port_t		tcp_port_delta_to_init	[USHRT_MAX];

/* Listening sockets, used for automatic port forwarding in pasta mode only */
static int tcp_sock_init_lo	[USHRT_MAX][IP_VERSIONS];
static int tcp_sock_init_ext	[USHRT_MAX][IP_VERSIONS];
static int tcp_sock_ns		[USHRT_MAX][IP_VERSIONS];

/* Table of destinations with very low RTT (assumed to be local), LRU */
static struct in6_addr low_rtt_dst[LOW_RTT_TABLE_SIZE];

/* Static buffers */

/**
 * tcp4_l2_buf_t - Pre-cooked IPv4 packet buffers for tap connections
 * @psum:	Partial IP header checksum (excluding tot_len and saddr)
 * @tsum:	Partial TCP header checksum (excluding length and saddr)
 * @pad:	Align TCP header to 32 bytes, for AVX2 checksum calculation only
 * @vnet_len:	4-byte qemu vnet buffer length descriptor, only for passt mode
 * @eh:		Pre-filled Ethernet header
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
	uint32_t vnet_len;	/* 26				10 */
	struct ethhdr eh;	/* 30				14 */
	struct iphdr iph;	/* 44				28 */
	struct tcphdr th;	/* 64				48 */
	uint8_t data[MSS4];	/* 84				68 */
				/* 65541			65525 */
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
tcp4_l2_buf[TCP_FRAMES_MEM];

static unsigned int tcp4_l2_buf_used;
static size_t tcp4_l2_buf_bytes;

/**
 * tcp6_l2_buf_t - Pre-cooked IPv6 packet buffers for tap connections
 * @pad:	Align IPv6 header for checksum calculation to 32B (AVX2) or 4B
 * @vnet_len:	4-byte qemu vnet buffer length descriptor, only for passt mode
 * @eh:		Pre-filled Ethernet header
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
	uint32_t vnet_len;	/* 14				2 */
	struct ethhdr eh;	/* 18				6 */
	struct ipv6hdr ip6h;	/* 32				20 */
	struct tcphdr th;	/* 72				60 */
	uint8_t data[MSS6];	/* 92				80 */
				/* 65639			65627 */
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
tcp6_l2_buf[TCP_FRAMES_MEM];

static unsigned int tcp6_l2_buf_used;
static size_t tcp6_l2_buf_bytes;

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
 * @vnet_len:	4-byte qemu vnet buffer length descriptor, only for passt mode
 * @eh:		Pre-filled Ethernet header
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
	uint32_t vnet_len;	/* 26				10 */
	struct ethhdr eh;	/* 30				14 */
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
static size_t tcp4_l2_flags_buf_bytes;

/**
 * tcp6_l2_flags_buf_t - IPv6 packet buffers for segments without data (flags)
 * @pad:	Align IPv6 header for checksum calculation to 32B (AVX2) or 4B
 * @vnet_len:	4-byte qemu vnet buffer length descriptor, only for passt mode
 * @eh:		Pre-filled Ethernet header
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
	uint32_t vnet_len;	/* 14					   2 */
	struct ethhdr eh;	/* 18					   6 */
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
static size_t tcp6_l2_flags_buf_bytes;

/* TCP connections */
static struct tcp_conn tc[TCP_MAX_CONNS];

/* Table for lookup from remote address, local port, remote port */
static struct tcp_conn *tc_hash[TCP_HASH_TABLE_SIZE];

/* Pools for pre-opened sockets */
int init_sock_pool4		[TCP_SOCK_POOL_SIZE];
int init_sock_pool6		[TCP_SOCK_POOL_SIZE];
int ns_sock_pool4		[TCP_SOCK_POOL_SIZE];
int ns_sock_pool6		[TCP_SOCK_POOL_SIZE];

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

static void conn_flag_do(const struct ctx *c, struct tcp_conn *conn,
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
static int tcp_epoll_ctl(const struct ctx *c, struct tcp_conn *conn)
{
	int m = (conn->flags & IN_EPOLL) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	union epoll_ref ref = { .r.proto = IPPROTO_TCP, .r.s = conn->sock,
				.r.p.tcp.tcp.index = conn - tc,
				.r.p.tcp.tcp.v6 = CONN_V6(conn) };
	struct epoll_event ev = { .data.u64 = ref.u64 };

	if (conn->events == CLOSED) {
		if (conn->flags & IN_EPOLL)
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->sock, &ev);
		if (conn->timer != -1)
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->timer, &ev);
		return 0;
	}

	ev.events = tcp_conn_epoll_events(conn->events, conn->flags);

	if (epoll_ctl(c->epollfd, m, conn->sock, &ev))
		return -errno;

	conn->flags |= IN_EPOLL;	/* No need to log this */

	if (conn->timer != -1) {
		union epoll_ref ref_t = { .r.proto = IPPROTO_TCP,
					  .r.s = conn->sock,
					  .r.p.tcp.tcp.timer = 1,
					  .r.p.tcp.tcp.index = conn - tc };
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
static void tcp_timer_ctl(const struct ctx *c, struct tcp_conn *conn)
{
	struct itimerspec it = { { 0 }, { 0 } };

	if (conn->events == CLOSED)
		return;

	if (conn->timer == -1) {
		union epoll_ref ref = { .r.proto = IPPROTO_TCP,
					.r.s = conn->sock,
					.r.p.tcp.tcp.timer = 1,
					.r.p.tcp.tcp.index = conn - tc };
		struct epoll_event ev = { .data.u64 = ref.u64,
					  .events = EPOLLIN | EPOLLET };
		int fd;

		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd == -1 || fd > SOCKET_MAX) {
			debug("TCP: failed to get timer: %s", strerror(errno));
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

	debug("TCP: index %li, timer expires in %lu.%03lus", conn - tc,
	      it.it_value.tv_sec, it.it_value.tv_nsec / 1000 / 1000);

	timerfd_settime(conn->timer, 0, &it, NULL);
}

/**
 * conn_flag_do() - Set/unset given flag, log, update epoll on STALLED flag
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flag:	Flag to set, or ~flag to unset
 */
static void conn_flag_do(const struct ctx *c, struct tcp_conn *conn,
			 unsigned long flag)
{
	if (flag & (flag - 1)) {
		if (!(conn->flags & ~flag))
			return;

		conn->flags &= flag;
		if (fls(~flag) >= 0) {
			debug("TCP: index %li: %s dropped", conn - tc,
			      tcp_flag_str[fls(~flag)]);
		}
	} else {
		if (conn->flags & flag)
			return;

		conn->flags |= flag;
		if (fls(flag) >= 0) {
			debug("TCP: index %li: %s", conn - tc,
			      tcp_flag_str[fls(flag)]);
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
static void conn_event_do(const struct ctx *c, struct tcp_conn *conn,
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
		debug("TCP: index %li, %s: %s -> %s", conn - tc,
		      num == -1 	       ? "CLOSED" : tcp_event_str[num],
		      prev == -1	       ? "CLOSED" : tcp_state_str[prev],
		      (new == -1 || num == -1) ? "CLOSED" : tcp_state_str[new]);
	} else {
		debug("TCP: index %li, %s", conn - tc,
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
 * tcp_remap_to_tap() - Set delta for port translation toward guest/tap
 * @port:	Original destination port, host order
 * @delta:	Delta to be added to original destination port
 */
void tcp_remap_to_tap(in_port_t port, in_port_t delta)
{
	tcp_port_delta_to_tap[port] = delta;
}

/**
 * tcp_remap_to_tap() - Set delta for port translation toward init namespace
 * @port:	Original destination port, host order
 * @delta:	Delta to be added to original destination port
 */
void tcp_remap_to_init(in_port_t port, in_port_t delta)
{
	tcp_port_delta_to_init[port] = delta;
}

/**
 * tcp_rtt_dst_low() - Check if low RTT was seen for connection endpoint
 * @conn:	Connection pointer
 *
 * Return: 1 if destination is in low RTT table, 0 otherwise
 */
static int tcp_rtt_dst_low(const struct tcp_conn *conn)
{
	int i;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++)
		if (IN6_ARE_ADDR_EQUAL(&conn->a.a6, low_rtt_dst + i))
			return 1;

	return 0;
}

/**
 * tcp_rtt_dst_check() - Check tcpi_min_rtt, insert endpoint in table if low
 * @conn:	Connection pointer
 * @tinfo:	Pointer to struct tcp_info for socket
 */
static void tcp_rtt_dst_check(const struct tcp_conn *conn,
			      const struct tcp_info *tinfo)
{
#ifdef HAS_MIN_RTT
	int i, hole = -1;

	if (!tinfo->tcpi_min_rtt ||
	    (int)tinfo->tcpi_min_rtt > LOW_RTT_THRESHOLD)
		return;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++) {
		if (IN6_ARE_ADDR_EQUAL(&conn->a.a6, low_rtt_dst + i))
			return;
		if (hole == -1 && IN6_IS_ADDR_UNSPECIFIED(low_rtt_dst + i))
			hole = i;
	}

	/* Keep gcc 12 happy: this won't actually happen because the table is
	 * guaranteed to have a hole, see the second memcpy() below.
	 */
	if (hole == -1)
		return;

	memcpy(low_rtt_dst + hole++, &conn->a.a6, sizeof(conn->a.a6));
	if (hole == LOW_RTT_TABLE_SIZE)
		hole = 0;
	memcpy(low_rtt_dst + hole, &in6addr_any, sizeof(conn->a.a6));
#else
	(void)conn;
	(void)tinfo;
#endif /* HAS_MIN_RTT */
}

/**
 * tcp_get_sndbuf() - Get, scale SO_SNDBUF between thresholds (1 to 0.5 usage)
 * @conn:	Connection pointer
 */
static void tcp_get_sndbuf(struct tcp_conn *conn)
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
		       const uint32_t *ip_da)
{
	int i;

	for (i = 0; i < TCP_FRAMES_MEM; i++) {
		struct tcp4_l2_flags_buf_t *b4f = &tcp4_l2_flags_buf[i];
		struct tcp6_l2_flags_buf_t *b6f = &tcp6_l2_flags_buf[i];
		struct tcp4_l2_buf_t *b4 = &tcp4_l2_buf[i];
		struct tcp6_l2_buf_t *b6 = &tcp6_l2_buf[i];

		if (eth_d) {
			memcpy(b4->eh.h_dest, eth_d, ETH_ALEN);
			memcpy(b6->eh.h_dest, eth_d, ETH_ALEN);

			memcpy(b4f->eh.h_dest, eth_d, ETH_ALEN);
			memcpy(b6f->eh.h_dest, eth_d, ETH_ALEN);
		}

		if (eth_s) {
			memcpy(b4->eh.h_source, eth_s, ETH_ALEN);
			memcpy(b6->eh.h_source, eth_s, ETH_ALEN);

			memcpy(b4f->eh.h_source, eth_s, ETH_ALEN);
			memcpy(b6f->eh.h_source, eth_s, ETH_ALEN);
		}

		if (ip_da) {
			b4f->iph.daddr = b4->iph.daddr = *ip_da;
			if (!i) {
				b4f->iph.saddr = b4->iph.saddr = 0;
				b4f->iph.tot_len = b4->iph.tot_len = 0;
				b4f->iph.check = b4->iph.check = 0;
				b4f->psum = b4->psum = sum_16b(&b4->iph, 20);

				b4->tsum = ((*ip_da >> 16) & 0xffff) +
					   (*ip_da & 0xffff) +
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
 */
static void tcp_sock4_iov_init(void)
{
	struct iovec *iov;
	int i;

	for (i = 0; i < ARRAY_SIZE(tcp4_l2_buf); i++) {
		tcp4_l2_buf[i] = (struct tcp4_l2_buf_t) { 0, 0,
			{ 0 },
			0, L2_BUF_ETH_IP4_INIT, L2_BUF_IP4_INIT(IPPROTO_TCP),
			{ .doff = sizeof(struct tcphdr) / 4, .ack = 1 }, { 0 },
		};
	}

	for (i = 0; i < ARRAY_SIZE(tcp4_l2_flags_buf); i++) {
		tcp4_l2_flags_buf[i] = (struct tcp4_l2_flags_buf_t) { 0, 0,
			{ 0 },
			0, L2_BUF_ETH_IP4_INIT, L2_BUF_IP4_INIT(IPPROTO_TCP),
			{ 0 }, { 0 },
		};
	}

	for (i = 0, iov = tcp4_l2_iov; i < TCP_FRAMES_MEM; i++, iov++) {
		iov->iov_base = &tcp4_l2_buf[i].vnet_len;
		iov->iov_len = MSS_DEFAULT;
	}

	for (i = 0, iov = tcp4_l2_flags_iov; i < TCP_FRAMES_MEM; i++, iov++)
		iov->iov_base = &tcp4_l2_flags_buf[i].vnet_len;
}

/**
 * tcp_sock6_iov_init() - Initialise scatter-gather L2 buffers for IPv6 sockets
 */
static void tcp_sock6_iov_init(void)
{
	struct iovec *iov;
	int i;

	for (i = 0; i < ARRAY_SIZE(tcp6_l2_buf); i++) {
		tcp6_l2_buf[i] = (struct tcp6_l2_buf_t) {
			{ 0 },
			0, L2_BUF_ETH_IP6_INIT, L2_BUF_IP6_INIT(IPPROTO_TCP),
			{ .doff = sizeof(struct tcphdr) / 4, .ack = 1 }, { 0 },
		};
	}

	for (i = 0; i < ARRAY_SIZE(tcp6_l2_flags_buf); i++) {
		tcp6_l2_flags_buf[i] = (struct tcp6_l2_flags_buf_t) {
			{ 0 },
			0, L2_BUF_ETH_IP6_INIT, L2_BUF_IP6_INIT(IPPROTO_TCP),
			{ 0 }, { 0 },
		};
	}

	for (i = 0, iov = tcp6_l2_iov; i < TCP_FRAMES_MEM; i++, iov++) {
		iov->iov_base = &tcp6_l2_buf[i].vnet_len;
		iov->iov_len = MSS_DEFAULT;
	}

	for (i = 0, iov = tcp6_l2_flags_iov; i < TCP_FRAMES_MEM; i++, iov++)
		iov->iov_base = &tcp6_l2_flags_buf[i].vnet_len;
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

	if (!len)
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
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: 1 on match, 0 otherwise
 */
static int tcp_hash_match(const struct tcp_conn *conn, int af, const void *addr,
			  in_port_t tap_port, in_port_t sock_port)
{
	if (af == AF_INET && CONN_V4(conn)			&&
	    !memcmp(&conn->a.a4.a, addr, sizeof(conn->a.a4.a))	&&
	    conn->tap_port == tap_port && conn->sock_port == sock_port)
		return 1;

	if (af == AF_INET6					&&
	    IN6_ARE_ADDR_EQUAL(&conn->a.a6, addr)		&&
	    conn->tap_port == tap_port && conn->sock_port == sock_port)
		return 1;

	return 0;
}

/**
 * tcp_hash() - Calculate hash value for connection given address and ports
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: hash value, already modulo size of the hash table
 */
#if TCP_HASH_NOINLINE
__attribute__((__noinline__))	/* See comment in Makefile */
#endif
static unsigned int tcp_hash(const struct ctx *c, int af, const void *addr,
			     in_port_t tap_port, in_port_t sock_port)
{
	uint64_t b = 0;

	if (af == AF_INET) {
		struct {
			struct in_addr addr;
			in_port_t tap_port;
			in_port_t sock_port;
		} __attribute__((__packed__)) in = {
			*(struct in_addr *)addr, tap_port, sock_port,
		};

		b = siphash_8b((uint8_t *)&in, c->tcp.hash_secret);
	} else if (af == AF_INET6) {
		struct {
			struct in6_addr addr;
			in_port_t tap_port;
			in_port_t sock_port;
		} __attribute__((__packed__)) in = {
			*(struct in6_addr *)addr, tap_port, sock_port,
		};

		b = siphash_20b((uint8_t *)&in, c->tcp.hash_secret);
	}

	return (unsigned int)(b % TCP_HASH_TABLE_SIZE);
}

/**
 * tcp_hash_insert() - Insert connection into hash table, chain link
 * @c:		Execution context
 * @conn:	Connection pointer
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 */
static void tcp_hash_insert(const struct ctx *c, struct tcp_conn *conn,
			    int af, const void *addr)
{
	int b;

	b = tcp_hash(c, af, addr, conn->tap_port, conn->sock_port);
	conn->next_index = tc_hash[b] ? tc_hash[b] - tc : -1;
	tc_hash[b] = conn;
	conn->hash_bucket = b;

	debug("TCP: hash table insert: index %li, sock %i, bucket: %i, next: "
	      "%p", conn - tc, conn->sock, b, CONN_OR_NULL(conn->next_index));
}

/**
 * tcp_hash_remove() - Drop connection from hash table, chain unlink
 * @conn:	Connection pointer
 */
static void tcp_hash_remove(const struct tcp_conn *conn)
{
	struct tcp_conn *entry, *prev = NULL;
	int b = conn->hash_bucket;

	for (entry = tc_hash[b]; entry;
	     prev = entry, entry = CONN_OR_NULL(entry->next_index)) {
		if (entry == conn) {
			if (prev)
				prev->next_index = conn->next_index;
			else
				tc_hash[b] = CONN_OR_NULL(conn->next_index);
			break;
		}
	}

	debug("TCP: hash table remove: index %li, sock %i, bucket: %i, new: %p",
	      conn - tc, conn->sock, b,
	      prev ? CONN_OR_NULL(prev->next_index) : tc_hash[b]);
}

/**
 * tcp_hash_update() - Update pointer for given connection
 * @old:	Old connection pointer
 * @new:	New connection pointer
 */
static void tcp_hash_update(struct tcp_conn *old, struct tcp_conn *new)
{
	struct tcp_conn *entry, *prev = NULL;
	int b = old->hash_bucket;

	for (entry = tc_hash[b]; entry;
	     prev = entry, entry = CONN_OR_NULL(entry->next_index)) {
		if (entry == old) {
			if (prev)
				prev->next_index = new - tc;
			else
				tc_hash[b] = new;
			break;
		}
	}

	debug("TCP: hash table update: old index %li, new index %li, sock %i, "
	      "bucket: %i, old: %p, new: %p",
	      old - tc, new - tc, new->sock, b, old, new);
}

/**
 * tcp_hash_lookup() - Look up connection given remote address and ports
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: connection pointer, if found, -ENOENT otherwise
 */
static struct tcp_conn *tcp_hash_lookup(const struct ctx *c, int af,
					const void *addr,
					in_port_t tap_port, in_port_t sock_port)
{
	int b = tcp_hash(c, af, addr, tap_port, sock_port);
	struct tcp_conn *conn;

	for (conn = tc_hash[b]; conn; conn = CONN_OR_NULL(conn->next_index)) {
		if (tcp_hash_match(conn, af, addr, tap_port, sock_port))
			return conn;
	}

	return NULL;
}

/**
 * tcp_table_compact() - Perform compaction on connection table
 * @c:		Execution context
 * @hole:	Pointer to recently closed connection
 */
static void tcp_table_compact(struct ctx *c, struct tcp_conn *hole)
{
	struct tcp_conn *from, *to;

	if ((hole - tc) == --c->tcp.conn_count) {
		debug("TCP: hash table compaction: maximum index was %li (%p)",
		      hole - tc, hole);
		memset(hole, 0, sizeof(*hole));
		return;
	}

	from = CONN(c->tcp.conn_count);
	memcpy(hole, from, sizeof(*hole));

	to = hole;
	tcp_hash_update(from, to);

	tcp_epoll_ctl(c, to);

	debug("TCP: hash table compaction: old index %li, new index %li, "
	      "sock %i, from: %p, to: %p",
	      from - tc, to - tc, from->sock, from, to);

	memset(from, 0, sizeof(*from));
}

/**
 * tcp_conn_destroy() - Close sockets, trigger hash table removal and compaction
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_conn_destroy(struct ctx *c, struct tcp_conn *conn)
{
	close(conn->sock);
	if (conn->timer != -1)
		close(conn->timer);

	tcp_hash_remove(conn);
	tcp_table_compact(c, conn);
}

static void tcp_rst_do(struct ctx *c, struct tcp_conn *conn);
#define tcp_rst(c, conn)						\
	do {								\
		debug("TCP: index %li, reset at %s:%i", conn - tc,	\
		      __func__, __LINE__);				\
		tcp_rst_do(c, conn);					\
	} while (0)

/**
 * tcp_l2_buf_write_one() - Write a single buffer to tap file descriptor
 * @c:		Execution context
 * @iov:	struct iovec item pointing to buffer
 * @ts:		Current timestamp
 *
 * Return: 0 on success, negative error code on failure (tap reset possible)
 */
static int tcp_l2_buf_write_one(struct ctx *c, const struct iovec *iov)
{
	if (write(c->fd_tap, (char *)iov->iov_base + 4, iov->iov_len - 4) < 0) {
		debug("tap write: %s", strerror(errno));
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			tap_handler(c, c->fd_tap, EPOLLERR, NULL);
		return -errno;
	}

	return 0;
}

/**
 * tcp_l2_buf_flush_part() - Ensure a complete last message on partial sendmsg()
 * @c:		Execution context
 * @mh:		Message header that was partially sent by sendmsg()
 * @sent:	Bytes already sent
 */
static void tcp_l2_buf_flush_part(const struct ctx *c,
				  const struct msghdr *mh, size_t sent)
{
	size_t end = 0, missing;
	struct iovec *iov;
	unsigned int i;
	char *p;

	for (i = 0, iov = mh->msg_iov; i < mh->msg_iovlen; i++, iov++) {
		end += iov->iov_len;
		if (end >= sent)
			break;
	}

	missing = end - sent;
	p = (char *)iov->iov_base + iov->iov_len - missing;
	if (send(c->fd_tap, p, missing, MSG_NOSIGNAL))
		debug("TCP: failed to flush %lu missing bytes to tap", missing);
}

/**
 * tcp_l2_flags_buf_flush() - Send out buffers for segments with or without data
 * @c:		Execution context
 * @mh:		Message header pointing to buffers, msg_iovlen not set
 * @buf_used:	Pointer to count of used buffers, set to 0 on return
 * @buf_bytes:	Pointer to count of buffer bytes, set to 0 on return
 */
static void tcp_l2_buf_flush(struct ctx *c, struct msghdr *mh,
			     unsigned int *buf_used, size_t *buf_bytes)
{
	if (!(mh->msg_iovlen = *buf_used))
		return;

	if (c->mode == MODE_PASST) {
		size_t n = sendmsg(c->fd_tap, mh, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n > 0 && n < *buf_bytes)
			tcp_l2_buf_flush_part(c, mh, n);
	} else {
		size_t i;

		for (i = 0; i < mh->msg_iovlen; i++) {
			struct iovec *iov = &mh->msg_iov[i];

			if (tcp_l2_buf_write_one(c, iov))
				i--;
		}
	}
	*buf_used = *buf_bytes = 0;
	pcapm(mh);
}

/**
 * tcp_l2_flags_buf_flush() - Send out buffers for segments with no data (flags)
 * @c:		Execution context
 */
static void tcp_l2_flags_buf_flush(struct ctx *c)
{
	struct msghdr mh = { 0 };
	unsigned int *buf_used;
	size_t *buf_bytes;

	mh.msg_iov	= tcp6_l2_flags_iov;
	buf_used	= &tcp6_l2_flags_buf_used;
	buf_bytes	= &tcp6_l2_flags_buf_bytes;
	tcp_l2_buf_flush(c, &mh, buf_used, buf_bytes);

	mh.msg_iov	= tcp4_l2_flags_iov;
	buf_used	= &tcp4_l2_flags_buf_used;
	buf_bytes	= &tcp4_l2_flags_buf_bytes;
	tcp_l2_buf_flush(c, &mh, buf_used, buf_bytes);
}

/**
 * tcp_l2_data_buf_flush() - Send out buffers for segments with data
 * @c:		Execution context
 */
static void tcp_l2_data_buf_flush(struct ctx *c)
{
	struct msghdr mh = { 0 };
	unsigned int *buf_used;
	size_t *buf_bytes;

	mh.msg_iov = tcp6_l2_iov;
	buf_used	= &tcp6_l2_buf_used;
	buf_bytes	= &tcp6_l2_buf_bytes;
	tcp_l2_buf_flush(c, &mh, buf_used, buf_bytes);

	mh.msg_iov = tcp4_l2_iov;
	buf_used	= &tcp4_l2_buf_used;
	buf_bytes	= &tcp4_l2_buf_bytes;
	tcp_l2_buf_flush(c, &mh, buf_used, buf_bytes);
}

/**
 * tcp_defer_handler() - Handler for TCP deferred tasks
 * @c:		Execution context
 */
void tcp_defer_handler(struct ctx *c)
{
	int max_conns = c->tcp.conn_count / 100 * TCP_CONN_PRESSURE;
	int max_files = c->nofile / 100 * TCP_FILE_PRESSURE;
	struct tcp_conn *conn;

	tcp_l2_flags_buf_flush(c);
	tcp_l2_data_buf_flush(c);

	tcp_splice_defer_handler(c);

	if (c->tcp.conn_count < MIN(max_files, max_conns))
		return;

	for (conn = CONN(c->tcp.conn_count - 1); conn >= tc; conn--) {
		if (conn->events == CLOSED)
			tcp_conn_destroy(c, conn);
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
 * Return: 802.3 length, host order
 */
static size_t tcp_l2_buf_fill_headers(const struct ctx *c,
				      const struct tcp_conn *conn,
				      void *p, size_t plen,
				      const uint16_t *check, uint32_t seq)
{
	size_t ip_len, eth_len;

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

	if (CONN_V6(conn)) {
		struct tcp6_l2_buf_t *b = (struct tcp6_l2_buf_t *)p;

		ip_len = plen + sizeof(struct ipv6hdr) + sizeof(struct tcphdr);

		b->ip6h.payload_len = htons(plen + sizeof(struct tcphdr));
		b->ip6h.saddr = conn->a.a6;
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

		eth_len = ip_len + sizeof(struct ethhdr);
		if (c->mode == MODE_PASST)
			b->vnet_len = htonl(eth_len);
	} else {
		struct tcp4_l2_buf_t *b = (struct tcp4_l2_buf_t *)p;

		ip_len = plen + sizeof(struct iphdr) + sizeof(struct tcphdr);
		b->iph.tot_len = htons(ip_len);
		b->iph.saddr = conn->a.a4.a.s_addr;
		b->iph.daddr = c->ip4.addr_seen;

		if (check)
			b->iph.check = *check;
		else
			tcp_update_check_ip4(b);

		SET_TCP_HEADER_COMMON_V4_V6(b, conn, seq);

		tcp_update_check_tcp4(b);

		eth_len = ip_len + sizeof(struct ethhdr);
		if (c->mode == MODE_PASST)
			b->vnet_len = htonl(eth_len);
	}

#undef SET_TCP_HEADER_COMMON_V4_V6

	return eth_len;
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
static int tcp_update_seqack_wnd(const struct ctx *c, struct tcp_conn *conn,
				 int force_seq, struct tcp_info *tinfo)
{
	uint32_t prev_wnd_to_tap = conn->wnd_to_tap << conn->ws_to_tap;
	uint32_t prev_ack_to_tap = conn->seq_ack_to_tap;
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
 * tcp_send_flag() - Send segment with flags to tap (no payload)
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags: if not set, send segment only if ACK is due
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
static int tcp_send_flag(struct ctx *c, struct tcp_conn *conn, int flags)
{
	uint32_t prev_ack_to_tap = conn->seq_ack_to_tap;
	uint32_t prev_wnd_to_tap = conn->wnd_to_tap;
	struct tcp4_l2_flags_buf_t *b4 = NULL;
	struct tcp6_l2_flags_buf_t *b6 = NULL;
	struct tcp_info tinfo = { 0 };
	socklen_t sl = sizeof(tinfo);
	size_t optlen = 0, eth_len;
	int s = conn->sock;
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

	eth_len = tcp_l2_buf_fill_headers(c, conn, p, optlen,
					  NULL, conn->seq_to_tap);
	iov->iov_len = eth_len + sizeof(uint32_t);

	if (CONN_V4(conn))
		tcp4_l2_flags_buf_bytes += iov->iov_len;
	else
		tcp6_l2_flags_buf_bytes += iov->iov_len;

	if (th->ack)
		conn_flag(c, conn, ~ACK_TO_TAP_DUE);

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
			tcp4_l2_flags_buf_bytes += iov->iov_len;
		}

		if (tcp4_l2_flags_buf_used > ARRAY_SIZE(tcp4_l2_flags_buf) - 2)
			tcp_l2_flags_buf_flush(c);
	} else {
		if (flags & DUP_ACK) {
			memcpy(b6 + 1, b6, sizeof(*b6));
			(iov + 1)->iov_len = iov->iov_len;
			tcp6_l2_flags_buf_used++;
			tcp6_l2_flags_buf_bytes += iov->iov_len;
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
static void tcp_rst_do(struct ctx *c, struct tcp_conn *conn)
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
static void tcp_get_tap_ws(struct tcp_conn *conn,
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
static void tcp_clamp_window(const struct ctx *c, struct tcp_conn *conn,
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
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @dstport:	Destination port, connection-wise, network order
 * @srcport:	Source port, connection-wise, network order
 * @now:	Current timestamp
 *
 * Return: initial TCP sequence
 */
static uint32_t tcp_seq_init(const struct ctx *c, int af, const void *addr,
			     in_port_t dstport, in_port_t srcport,
			     const struct timespec *now)
{
	uint32_t ns, seq = 0;

	if (af == AF_INET) {
		struct {
			struct in_addr src;
			in_port_t srcport;
			struct in_addr dst;
			in_port_t dstport;
		} __attribute__((__packed__)) in = {
			.src = *(struct in_addr *)addr,
			.srcport = srcport,
			.dst = { c->ip4.addr },
			.dstport = dstport,
		};

		seq = siphash_12b((uint8_t *)&in, c->tcp.hash_secret);
	} else if (af == AF_INET6) {
		struct {
			struct in6_addr src;
			in_port_t srcport;
			struct in6_addr dst;
			in_port_t dstport;
		} __attribute__((__packed__)) in = {
			.src = *(struct in6_addr *)addr,
			.srcport = srcport,
			.dst = c->ip6.addr,
			.dstport = dstport,
		};

		seq = siphash_36b((uint8_t *)&in, c->tcp.hash_secret);
	}

	ns = now->tv_sec * 1E9;
	ns += now->tv_nsec >> 5; /* 32ns ticks, overflows 32 bits every 137s */

	return seq + ns;
}

/**
 * tcp_conn_new_sock() - Get socket for new connection from pool or make new one
 * @c:		Execution context
 * @af:		Address family
 *
 * Return: socket number if available, negative code if socket creation failed
 */
static int tcp_conn_new_sock(const struct ctx *c, sa_family_t af)
{
	int *p = af == AF_INET6 ? init_sock_pool6 : init_sock_pool4, i, s = -1;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++, p++) {
		SWAP(s, *p);
		if (s >= 0)
			break;
	}

	if (s < 0)
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
 * @c:		Execution context
 * @conn:	Connection pointer
 * @opts:	Pointer to start of TCP options
 * @optlen:	Bytes in options: caller MUST ensure available length
 *
 * Return: clamped MSS value
 */
static uint16_t tcp_conn_tap_mss(const struct ctx *c,
				 const struct tcp_conn *conn,
				 const char *opts, size_t optlen)
{
	unsigned int mss;
	int ret;

	if ((ret = tcp_opt_get(opts, optlen, OPT_MSS, NULL, NULL)) < 0)
		mss = MSS_DEFAULT;
	else
		mss = ret;

	/* Don't upset qemu */
	if (c->mode == MODE_PASST) {
		if (CONN_V4(conn))
			mss = MIN(MSS4, mss);
		else
			mss = MIN(MSS6, mss);
	}

	return MIN(mss, USHRT_MAX);
}

/**
 * tcp_conn_from_tap() - Handle connection request (SYN segment) from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @th:		TCP header from tap: caller MUST ensure it's there
 * @opts:	Pointer to start of options
 * @optlen:	Bytes in options: caller MUST ensure available length
 * @now:	Current timestamp
 */
static void tcp_conn_from_tap(struct ctx *c, int af, const void *addr,
			      const struct tcphdr *th, const char *opts,
			      size_t optlen, const struct timespec *now)
{
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
	struct tcp_conn *conn;
	socklen_t sl;
	int s, mss;

	if (c->tcp.conn_count >= TCP_MAX_CONNS)
		return;

	if ((s = tcp_conn_new_sock(c, af)) < 0)
		return;

	if (!c->no_map_gw) {
		if (af == AF_INET && addr4.sin_addr.s_addr == c->ip4.gw)
			addr4.sin_addr.s_addr	= htonl(INADDR_LOOPBACK);
		if (af == AF_INET6 && IN6_ARE_ADDR_EQUAL(addr, &c->ip6.gw))
			addr6.sin6_addr		= in6addr_loopback;
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
	conn->sock = s;
	conn->timer = -1;
	conn_event(c, conn, TAP_SYN_RCVD);

	conn->wnd_to_tap = WINDOW_DEFAULT;

	mss = tcp_conn_tap_mss(c, conn, opts, optlen);
	if (setsockopt(s, SOL_TCP, TCP_MAXSEG, &mss, sizeof(mss)))
		trace("TCP: failed to set TCP_MAXSEG on socket %i", s);
	MSS_SET(conn, mss);

	tcp_get_tap_ws(conn, opts, optlen);

	/* RFC 7323, 2.2: first value is not scaled. Also, don't clamp yet, to
	 * avoid getting a zero scale just because we set a small window now.
	 */
	if (!(conn->wnd_from_tap = (htons(th->window) >> conn->ws_from_tap)))
		conn->wnd_from_tap = 1;

	if (af == AF_INET) {
		sa = (struct sockaddr *)&addr4;
		sl = sizeof(addr4);

		memset(&conn->a.a4.zero, 0,    sizeof(conn->a.a4.zero));
		memset(&conn->a.a4.one,  0xff, sizeof(conn->a.a4.one));
		memcpy(&conn->a.a4.a,    addr, sizeof(conn->a.a4.a));
	} else {
		sa = (struct sockaddr *)&addr6;
		sl = sizeof(addr6);

		memcpy(&conn->a.a6,      addr, sizeof(conn->a.a6));
	}

	conn->sock_port = ntohs(th->dest);
	conn->tap_port = ntohs(th->source);

	conn->seq_init_from_tap = ntohl(th->seq);
	conn->seq_from_tap = conn->seq_init_from_tap + 1;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	conn->seq_to_tap = tcp_seq_init(c, af, addr, th->dest, th->source, now);
	conn->seq_ack_from_tap = conn->seq_to_tap + 1;

	tcp_hash_insert(c, conn, af, addr);

	if (!bind(s, sa, sl)) {
		tcp_rst(c, conn);	/* Nobody is listening then */
		return;
	}
	if (errno != EADDRNOTAVAIL && errno != EACCES)
		conn_flag(c, conn, LOCAL);

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
static int tcp_sock_consume(struct tcp_conn *conn, uint32_t ack_seq)
{
	/* Simply ignore out-of-order ACKs: we already consumed the data we
	 * needed from the buffer, and we won't rewind back to a lower ACK
	 * sequence.
	 */
	if (SEQ_LE(ack_seq, conn->seq_ack_from_tap))
		return 0;

	if (recv(conn->sock, NULL, ack_seq - conn->seq_ack_from_tap,
		 MSG_DONTWAIT | MSG_TRUNC) < 0)
		return -errno;

	conn->seq_ack_from_tap = ack_seq;
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
static void tcp_data_to_tap(struct ctx *c, struct tcp_conn *conn,
			    ssize_t plen, int no_csum, uint32_t seq)
{
	struct iovec *iov;
	size_t len;

	if (CONN_V4(conn)) {
		struct tcp4_l2_buf_t *b = &tcp4_l2_buf[tcp4_l2_buf_used];
		uint16_t *check = no_csum ? &(b - 1)->iph.check : NULL;

		len = tcp_l2_buf_fill_headers(c, conn, b, plen, check, seq);

		iov = tcp4_l2_iov + tcp4_l2_buf_used++;
		tcp4_l2_buf_bytes += iov->iov_len = len + sizeof(b->vnet_len);
		if (tcp4_l2_buf_used > ARRAY_SIZE(tcp4_l2_buf) - 1)
			tcp_l2_data_buf_flush(c);
	} else if (CONN_V6(conn)) {
		struct tcp6_l2_buf_t *b = &tcp6_l2_buf[tcp6_l2_buf_used];

		len = tcp_l2_buf_fill_headers(c, conn, b, plen, NULL, seq);

		iov = tcp6_l2_iov + tcp6_l2_buf_used++;
		tcp6_l2_buf_bytes += iov->iov_len = len + sizeof(b->vnet_len);
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
static int tcp_data_from_sock(struct ctx *c, struct tcp_conn *conn)
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
recvmsg:
	len = recvmsg(s, &mh_sock, MSG_PEEK);
	if (len < 0) {
		if (errno == EINTR)
			goto recvmsg;
		goto err;
	}

	if (!len)
		goto zero_len;

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

zero_len:
	if ((conn->events & (SOCK_FIN_RCVD | TAP_FIN_SENT)) == SOCK_FIN_RCVD) {
		if ((ret = tcp_send_flag(c, conn, FIN | ACK))) {
			tcp_rst(c, conn);
			return ret;
		}

		conn_event(c, conn, TAP_FIN_SENT);
	}

	return 0;
}

/**
 * tcp_data_from_tap() - tap/guest data for established connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @p:		Pool of TCP packets, with TCP headers
 *
 * #syscalls sendmsg
 */
static void tcp_data_from_tap(struct ctx *c, struct tcp_conn *conn,
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

	if (ack) {
		if (max_ack_seq == conn->seq_to_tap) {
			conn_flag(c, conn, ~ACK_FROM_TAP_DUE);
			conn->retrans = 0;
		}

		tcp_sock_consume(conn, max_ack_seq);
	}

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
static void tcp_conn_from_sock_finish(struct ctx *c, struct tcp_conn *conn,
				      const struct tcphdr *th,
				      const char *opts, size_t optlen)
{
	tcp_clamp_window(c, conn, ntohs(th->window));
	tcp_get_tap_ws(conn, opts, optlen);

	/* First value is not scaled */
	if (!(conn->wnd_from_tap >>= conn->ws_from_tap))
		conn->wnd_from_tap = 1;

	MSS_SET(conn, tcp_conn_tap_mss(c, conn, opts, optlen));

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
	struct tcp_conn *conn;
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

	trace("TCP: packet length %lu from tap for index %lu", len, conn - tc);

	if (th->rst) {
		conn_event(c, conn, CLOSED);
		return p->count;
	}

	if (th->ack) {
		conn_flag(c, conn, ~ACK_FROM_TAP_DUE);
		conn->retrans = 0;
	}

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
static void tcp_connect_finish(struct ctx *c, struct tcp_conn *conn)
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
 * tcp_conn_from_sock() - Handle new connection request from listening socket
 * @c:		Execution context
 * @ref:	epoll reference of listening socket
 * @now:	Current timestamp
 */
static void tcp_conn_from_sock(struct ctx *c, union epoll_ref ref,
			       const struct timespec *now)
{
	struct sockaddr_storage sa;
	struct tcp_conn *conn;
	socklen_t sl;
	int s;

	if (c->tcp.conn_count >= TCP_MAX_CONNS)
		return;

	sl = sizeof(sa);
	s = accept4(ref.r.s, (struct sockaddr *)&sa, &sl, SOCK_NONBLOCK);
	if (s < 0)
		return;

	conn = CONN(c->tcp.conn_count++);
	conn->sock = s;
	conn->timer = -1;
	conn->ws_to_tap = conn->ws_from_tap = 0;
	conn_event(c, conn, SOCK_ACCEPTED);

	if (ref.r.p.tcp.tcp.v6) {
		struct sockaddr_in6 sa6;

		memcpy(&sa6, &sa, sizeof(sa6));

		if (IN6_IS_ADDR_LOOPBACK(&sa6.sin6_addr) ||
		    IN6_ARE_ADDR_EQUAL(&sa6.sin6_addr, &c->ip6.addr_seen) ||
		    IN6_ARE_ADDR_EQUAL(&sa6.sin6_addr, &c->ip6.addr)) {
			struct in6_addr *src;

			if (IN6_IS_ADDR_LINKLOCAL(&c->ip6.gw))
				src = &c->ip6.gw;
			else
				src = &c->ip6.addr_ll;

			memcpy(&sa6.sin6_addr, src, sizeof(*src));
		}

		memcpy(&conn->a.a6, &sa6.sin6_addr, sizeof(conn->a.a6));

		conn->sock_port = ntohs(sa6.sin6_port);
		conn->tap_port = ref.r.p.tcp.tcp.index;

		conn->seq_to_tap = tcp_seq_init(c, AF_INET6, &sa6.sin6_addr,
						conn->sock_port,
						conn->tap_port,
						now);

		tcp_hash_insert(c, conn, AF_INET6, &sa6.sin6_addr);
	} else {
		struct sockaddr_in sa4;
		in_addr_t s_addr;

		memcpy(&sa4, &sa, sizeof(sa4));
		s_addr = ntohl(sa4.sin_addr.s_addr);

		memset(&conn->a.a4.zero,   0, sizeof(conn->a.a4.zero));
		memset(&conn->a.a4.one, 0xff, sizeof(conn->a.a4.one));

		if (s_addr >> IN_CLASSA_NSHIFT == IN_LOOPBACKNET ||
		    s_addr == INADDR_ANY || htonl(s_addr) == c->ip4.addr_seen)
			s_addr = ntohl(c->ip4.gw);

		s_addr = htonl(s_addr);
		memcpy(&conn->a.a4.a, &s_addr, sizeof(conn->a.a4.a));

		conn->sock_port = ntohs(sa4.sin_port);
		conn->tap_port = ref.r.p.tcp.tcp.index;

		conn->seq_to_tap = tcp_seq_init(c, AF_INET, &s_addr,
						conn->sock_port,
						conn->tap_port,
						now);

		tcp_hash_insert(c, conn, AF_INET, &s_addr);
	}

	conn->seq_ack_from_tap = conn->seq_to_tap + 1;

	conn->wnd_from_tap = WINDOW_DEFAULT;

	tcp_send_flag(c, conn, SYN);
	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	tcp_get_sndbuf(conn);
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
	struct tcp_conn *conn = CONN_OR_NULL(ref.r.p.tcp.tcp.index);
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
		conn_flag(c, conn, ~ACK_TO_TAP_DUE);
	} else if (conn->flags & ACK_FROM_TAP_DUE) {
		if (!(conn->events & ESTABLISHED)) {
			debug("TCP: index %li, handshake timeout", conn - tc);
			tcp_rst(c, conn);
		} else if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED)) {
			debug("TCP: index %li, FIN timeout", conn - tc);
			tcp_rst(c, conn);
		} else if (conn->retrans == TCP_MAX_RETRANS) {
			debug("TCP: index %li, retransmissions count exceeded",
			      conn - tc);
			tcp_rst(c, conn);
		} else {
			debug("TCP: index %li, ACK timeout, retry", conn - tc);
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
			debug("TCP: index %li, activity timeout", conn - tc);
			tcp_rst(c, conn);
		}
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
	struct tcp_conn *conn;

	if (ref.r.p.tcp.tcp.timer) {
		tcp_timer_handler(c, ref);
		return;
	}

	if (ref.r.p.tcp.tcp.splice) {
		tcp_sock_handler_splice(c, ref, events);
		return;
	}

	if (ref.r.p.tcp.tcp.listen) {
		tcp_conn_from_sock(c, ref, now);
		return;
	}

	if (!(conn = CONN_OR_NULL(ref.r.p.tcp.tcp.index)))
		return;

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
 * tcp_sock_init() - Initialise listening sockets for a given port
 * @c:		Execution context
 * @ns:		In pasta mode, if set, bind with loopback address in namespace
 * @af:		Address family to select a specific IP version, or AF_UNSPEC
 * @addr:	Pointer to address for binding, NULL if not configured
 * @port:	Port, host order
 */
void tcp_sock_init(const struct ctx *c, int ns, sa_family_t af,
		   const void *addr, in_port_t port)
{
	union tcp_epoll_ref tref = { .tcp.listen = 1 };
	const void *bind_addr;
	int s;

	if (ns) {
		tref.tcp.index = (in_port_t)(port +
					     tcp_port_delta_to_init[port]);
	} else {
		tref.tcp.index = (in_port_t)(port +
					     tcp_port_delta_to_tap[port]);
	}

	if (af == AF_INET || af == AF_UNSPEC) {
		if (!addr && c->mode == MODE_PASTA)
			bind_addr = &c->ip4.addr;
		else
			bind_addr = addr;

		tref.tcp.v6 = 0;
		tref.tcp.splice = 0;

		if (!ns) {
			s = sock_l4(c, AF_INET, IPPROTO_TCP, bind_addr, port,
				    tref.u32);
			if (s >= 0)
				tcp_sock_set_bufsize(c, s);
			else
				s = -1;

			if (c->tcp.init_detect_ports)
				tcp_sock_init_ext[port][V4] = s;
		}

		if (c->mode == MODE_PASTA) {
			bind_addr = &(uint32_t){ htonl(INADDR_LOOPBACK) };

			tref.tcp.splice = 1;
			s = sock_l4(c, AF_INET, IPPROTO_TCP, bind_addr, port,
				    tref.u32);
			if (s >= 0)
				tcp_sock_set_bufsize(c, s);
			else
				s = -1;

			if (c->tcp.ns_detect_ports) {
				if (ns)
					tcp_sock_ns[port][V4] = s;
				else
					tcp_sock_init_lo[port][V4] = s;
			}
		}
	}

	if (af == AF_INET6 || af == AF_UNSPEC) {
		if (!addr && c->mode == MODE_PASTA)
			bind_addr = &c->ip6.addr;
		else
			bind_addr = addr;

		tref.tcp.v6 = 1;

		tref.tcp.splice = 0;
		if (!ns) {
			s = sock_l4(c, AF_INET6, IPPROTO_TCP, bind_addr, port,
				    tref.u32);
			if (s >= 0)
				tcp_sock_set_bufsize(c, s);
			else
				s = -1;

			if (c->tcp.init_detect_ports)
				tcp_sock_init_ext[port][V6] = s;
		}

		if (c->mode == MODE_PASTA) {
			bind_addr = &in6addr_loopback;

			tref.tcp.splice = 1;
			s = sock_l4(c, AF_INET6, IPPROTO_TCP, bind_addr, port,
				    tref.u32);
			if (s >= 0)
				tcp_sock_set_bufsize(c, s);
			else
				s = -1;

			if (c->tcp.ns_detect_ports) {
				if (ns)
					tcp_sock_ns[port][V6] = s;
				else
					tcp_sock_init_lo[port][V6] = s;
			}
		}
	}
}

/**
 * tcp_sock_init_ns() - Bind sockets in namespace for inbound connections
 * @arg:	Execution context
 *
 * Return: 0
 */
static int tcp_sock_init_ns(void *arg)
{
	struct ctx *c = (struct ctx *)arg;
	int port;

	ns_enter(c);

	for (port = 0; port < USHRT_MAX; port++) {
		if (!bitmap_isset(c->tcp.port_to_init, port))
			continue;

		tcp_sock_init(c, 1, AF_UNSPEC, NULL, port);
	}

	return 0;
}

/**
 * struct tcp_sock_refill_arg - Arguments for tcp_sock_refill()
 * @c:		Execution context
 * @ns:		Set to refill pool of sockets created in namespace
 */
struct tcp_sock_refill_arg {
	struct ctx *c;
	int ns;
};

/**
 * tcp_sock_refill() - Refill pool of pre-opened sockets
 * @arg:	See @tcp_sock_refill_arg
 *
 * Return: 0
 */
static int tcp_sock_refill(void *arg)
{
	struct tcp_sock_refill_arg *a = (struct tcp_sock_refill_arg *)arg;
	int i, *p4, *p6;

	if (a->ns) {
		ns_enter(a->c);
		p4 = ns_sock_pool4;
		p6 = ns_sock_pool6;
	} else {
		p4 = init_sock_pool4;
		p6 = init_sock_pool6;
	}

	for (i = 0; a->c->ifi4 && i < TCP_SOCK_POOL_SIZE; i++, p4++) {
		if (*p4 >= 0)
			break;

		*p4 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
		if (*p4 > SOCKET_MAX) {
			close(*p4);
			*p4 = -1;
			return -EIO;
		}

		if (*p4 >= 0)
			tcp_sock_set_bufsize(a->c, *p4);
	}

	for (i = 0; a->c->ifi6 && i < TCP_SOCK_POOL_SIZE; i++, p6++) {
		if (*p6 >= 0)
			break;

		*p6 = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK,
			     IPPROTO_TCP);
		if (*p6 > SOCKET_MAX) {
			close(*p6);
			*p6 = -1;
			return -EIO;
		}

		if (*p6 >= 0)
			tcp_sock_set_bufsize(a->c, *p6);
	}

	return 0;
}

/**
 * tcp_init() - Get initial sequence, hash secret, initialise per-socket data
 * @c:		Execution context
 *
 * Return: 0, doesn't return on failure
 */
int tcp_init(struct ctx *c)
{
	struct tcp_sock_refill_arg refill_arg = { c, 0 };
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
		tcp_sock4_iov_init();

	if (c->ifi6)
		tcp_sock6_iov_init();

	memset(init_sock_pool4,		0xff,	sizeof(init_sock_pool4));
	memset(init_sock_pool6,		0xff,	sizeof(init_sock_pool6));
	memset(ns_sock_pool4,		0xff,	sizeof(ns_sock_pool4));
	memset(ns_sock_pool6,		0xff,	sizeof(ns_sock_pool6));
	memset(tcp_sock_init_lo,	0xff,	sizeof(tcp_sock_init_lo));
	memset(tcp_sock_init_ext,	0xff,	sizeof(tcp_sock_init_ext));
	memset(tcp_sock_ns,		0xff,	sizeof(tcp_sock_ns));

	tcp_sock_refill(&refill_arg);

	if (c->mode == MODE_PASTA) {
		tcp_splice_init(c);

		NS_CALL(tcp_sock_init_ns, c);

		refill_arg.ns = 1;
		NS_CALL(tcp_sock_refill, &refill_arg);

		tcp_splice_timer(c);
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
	int port;

	if (a->bind_in_ns) {
		ns_enter(a->c);

		for (port = 0; port < USHRT_MAX; port++) {
			if (!bitmap_isset(a->c->tcp.port_to_init, port)) {
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
			if (bitmap_isset(a->c->tcp.port_to_tap, port))
				continue;

			if ((a->c->ifi4 && tcp_sock_ns[port][V4] == -1) ||
			    (a->c->ifi6 && tcp_sock_ns[port][V6] == -1))
				tcp_sock_init(a->c, 1, AF_UNSPEC, NULL, port);
		}
	} else {
		for (port = 0; port < USHRT_MAX; port++) {
			if (!bitmap_isset(a->c->tcp.port_to_tap, port)) {
				if (tcp_sock_init_ext[port][V4] >= 0) {
					close(tcp_sock_init_ext[port][V4]);
					tcp_sock_init_ext[port][V4] = -1;
				}

				if (tcp_sock_init_ext[port][V6] >= 0) {
					close(tcp_sock_init_ext[port][V6]);
					tcp_sock_init_ext[port][V6] = -1;
				}

				if (tcp_sock_init_lo[port][V4] >= 0) {
					close(tcp_sock_init_lo[port][V4]);
					tcp_sock_init_lo[port][V4] = -1;
				}

				if (tcp_sock_init_lo[port][V6] >= 0) {
					close(tcp_sock_init_lo[port][V6]);
					tcp_sock_init_lo[port][V6] = -1;
				}
				continue;
			}

			/* Don't loop back our own ports */
			if (bitmap_isset(a->c->tcp.port_to_init, port))
				continue;

			if ((a->c->ifi4 && tcp_sock_init_ext[port][V4] == -1) ||
			    (a->c->ifi6 && tcp_sock_init_ext[port][V6] == -1))
				tcp_sock_init(a->c, 0, AF_UNSPEC, NULL, port);
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
	struct tcp_sock_refill_arg refill_arg = { c, 0 };
	struct tcp_conn *conn;

	(void)ts;

	if (c->mode == MODE_PASTA) {
		struct tcp_port_detect_arg detect_arg = { c, 0 };
		struct tcp_port_rebind_arg rebind_arg = { c, 0 };

		if (c->tcp.init_detect_ports) {
			detect_arg.detect_in_ns = 0;
			tcp_port_detect(&detect_arg);
			rebind_arg.bind_in_ns = 1;
			NS_CALL(tcp_port_rebind, &rebind_arg);
		}

		if (c->tcp.ns_detect_ports) {
			detect_arg.detect_in_ns = 1;
			NS_CALL(tcp_port_detect, &detect_arg);
			rebind_arg.bind_in_ns = 0;
			tcp_port_rebind(&rebind_arg);
		}
	}

	for (conn = CONN(c->tcp.conn_count - 1); conn >= tc; conn--) {
		if (conn->events == CLOSED)
			tcp_conn_destroy(c, conn);
	}

	tcp_sock_refill(&refill_arg);
	if (c->mode == MODE_PASTA) {
		refill_arg.ns = 1;
		if ((c->ifi4 && ns_sock_pool4[TCP_SOCK_POOL_TSH] < 0) ||
		    (c->ifi6 && ns_sock_pool6[TCP_SOCK_POOL_TSH] < 0))
			NS_CALL(tcp_sock_refill, &refill_arg);

		tcp_splice_timer(c);
	}
}

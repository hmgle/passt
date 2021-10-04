// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp.c - TCP L2-L4 translation state machine
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
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
 *     machine focused on the translation of observed states instead
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
 * of connections is defined by MAX_TAP_CONNS below (currently 128k).
 *
 * Data needs to linger on sockets as long as it's not acknowledged by the
 * guest, and is read using MSG_PEEK into preallocated static buffers sized
 * to the maximum supported window, 64MiB ("discard" buffer, for already-sent
 * data) plus a number of maximum-MSS-sized buffers. This imposes a practical
 * limitation on window scaling, that is, the maximum factor is 1024. Larger
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
 * Connections are tracked by the @tt array of struct tcp_tap_conn, containing
 * addresses, ports, TCP states and parameters. This is statically allocated and
 * indexed by an arbitrary connection number. The array is compacted whenever a
 * connection is closed, by remapping the highest connection index in use to the
 * one freed up.
 *
 * References used for the epoll interface report the connection index used for
 * the @tt array.
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
 * States and events
 * -----------------
 *
 * These states apply to connected sockets only, listening sockets are always
 * open after initialisation, in LISTEN state. A single state is maintained for
 * both sides of the connection, and some states are omitted as they are already
 * handled by host kernel and guest.
 *
 * - CLOSED			no connection
 *   No associated events: this is always a final state, new connections
 *   directly start from TAP_SYN_SENT or SOCK_SYN_SENT described below.
 *
 * - TAP_SYN_SENT		connect() in progress, triggered from tap
 *   - connect() completes	SYN,ACK to tap > TAP_SYN_RCVD
 *   - connect() aborts		RST to tap, close socket > CLOSED
 *
 * - SOCK_SYN_SENT		new connected socket, SYN sent to tap
 *   - SYN,ACK from tap		ACK to tap > ESTABLISHED
 *   - SYN,ACK timeout		RST to tap, close socket > CLOSED
 *
 * - TAP_SYN_RCVD		connect() completed, SYN,ACK sent to tap
 *   - FIN from tap		write shutdown > FIN_WAIT_1
 *   - ACK from tap		> ESTABLISHED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *
 * - ESTABLISHED		connection established, ready for data
 *   - EPOLLRDHUP		read shutdown > ESTABLISHED_SOCK_FIN
 *   - FIN from tap		write shutdown > FIN_WAIT_1
 *   - EPOLLHUP			RST to tap, close socket > CLOSED
 *   - data timeout		read shutdown, FIN to tap >
 * 				ESTABLISHED_SOCK_FIN_SENT
 *
 * - ESTABLISHED_SOCK_FIN	socket closing connection, reading half closed
 *   - zero-sized socket read	FIN,ACK to tap > ESTABLISHED_SOCK_FIN_SENT
 *
 * - ESTABLISHED_SOCK_FIN_SENT	socket closing connection, FIN sent to tap
 *   - ACK (for FIN) from tap	> CLOSE_WAIT
 *   - tap ACK timeout		RST to tap, close socket > CLOSED
 *
 * - CLOSE_WAIT			socket closing connection, ACK from tap
 *   - FIN from tap		write shutdown > LAST_ACK
 *   - data timeout		RST to tap, close socket > CLOSED
 * 
 * - LAST_ACK			socket started close, tap completed it
 *   - any event from socket	ACK to tap, close socket > CLOSED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *
 * - FIN_WAIT_1			tap closing connection, FIN sent to socket
 *   - EPOLLRDHUP		FIN,ACK to tap, shutdown > FIN_WAIT_1_SOCK_FIN
 *   - socket timeout		RST to tap, close socket > CLOSED
 *
 * - FIN_WAIT_1_SOCK_FIN	tap closing connection, FIN received from socket
 *   - ACK from tap		close socket > CLOSED
 *   - tap ACK timeout		RST to tap, close socket > CLOSED
 *
 * - from any state
 *   - RST from tap		close socket > CLOSED
 *   - socket error		RST to tap, close socket > CLOSED
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
 * A bitmap of TCP_MAX_CONNS bits indicate the connections subject to timed
 * events based on states:
 * - SOCK_SYN_SENT: after a 2MSL (240s) timeout waiting for a SYN,ACK segment
 *   from tap expires, connection is reset (RST to tap, socket closed)
 * - TAP_SYN_RCVD: after a 2MSL (240s) timeout waiting for an ACK segment from
 *   tap expires, connection is reset (RST to tap, socket closed)
 * - TAP_SYN_SENT: connect() is pending, timeout is handled implicitly by
 *   connect() timeout, connection will be reset in case
 * - ESTABLISHED, ESTABLISHED_SOCK_FIN: if an ACK segment to tap is pending,
 *   bytes acknowledged by socket endpoint are checked every 50ms (one quarter
 *   of current TCP_DELACK_MAX on Linux)
 * - ESTABLISHED, ESTABLISHED_SOCK_FIN: after a timeout of 3s (TODO: implement
 *   requirements from RFC 6298) waiting for an ACK segment from tap expires,
 *   data from socket queue is retransmitted starting from the last ACK sequence
 * - ESTABLISHED, ESTABLISHED_SOCK_FIN: after a two hours (current
 *   TCP_KEEPALIVE_TIME on Linux) timeout waiting for any activity expires,
 *   connection is reset (RST to tap, socket closed)
 * - ESTABLISHED_SOCK_FIN: after a 2MSL (240s) timeout waiting for an ACK
 *   segment from tap expires, connection is reset (RST to tap, socket closed)
 * - CLOSE_WAIT: after a 2MSL (240s) timeout waiting for a FIN segment from tap
 *   expires, connection is reset (RST to tap, socket closed)
 * - FIN_WAIT_1: after a 2MSL (240s) timeout waiting for an ACK segment from
 *   socet expires, connection is reset (RST to tap, socket closed)
 * - FIN_WAIT_1_SOCK_FIN: after a 2MSL (240s) timeout waiting for an ACK segment
 *   from tap expires, connection is reset (RST to tap, socket closed)
 * - LAST_ACK: after a 2MSL (240s) timeout waiting for an ACK segment from
 *   socket expires, connection is reset (RST to tap, socket closed)
 *
 *
 * Data flows (from ESTABLISHED, ESTABLISHED_SOCK_FIN states)
 * ----------------------------------------------------------
 *
 * @seq_to_tap:		next sequence for packets to tap
 * @seq_ack_from_tap:	last ACK number received from tap
 * @seq_from_tap:	next sequence for packets from tap (not actually sent)
 * @seq_ack_to_tap:	last ACK number sent to tap
 *
 * @seq_init_from_tap:	initial sequence number from tap
 *
 * @wnd_from_tap:	last window size received from tap, scaled
 * 
 * - from socket to tap:
 *   - on new data from socket:
 *     - peek into buffer
 *     - send data to tap:
 *       - starting at offset (@seq_to_tap - @seq_ack_from_tap)
 *       - in MSS-sized segments
 *       - increasing @seq_to_tap at each segment
 *       - up to window (until @seq_to_tap - @seq_ack_from_tap <= @wnd_from_tap)
 *       - mark socket in bitmap for periodic ACK check, set @last_ts_to_tap
 *     - on read error, send RST to tap, close socket
 *     - on zero read, send FIN to tap, enter ESTABLISHED_SOCK_FIN
 *   - on ACK from tap:
 *     - set @ts_ack_tap
 *     - check if it's the second duplicated ACK
 *     - consume buffer by difference between new ack_seq and @seq_ack_from_tap
 *     - update @seq_ack_from_tap from ack_seq in header
 *     - on two duplicated ACKs, reset @seq_to_tap to @seq_ack_from_tap, and
 *       resend with steps listed above
 *     - set TCP_WINDOW_CLAMP from TCP header from tap
 *     - on @seq_ack_from_tap == @seq_to_tap, mark in bitmap, umark otherwise
 *   - periodically:
 *     - if @seq_ack_from_tap < @seq_to_tap and the retransmission timer
 *       (TODO: implement requirements from RFC 6298, currently 3s fixed) from
 *       @ts_tap_from_ack elapsed, reset @seq_to_tap to @seq_ack_from_tap, and
 *       resend data with the steps listed above
 *
 * - from tap to socket:
 *   - on packet from tap:
 *     - set @ts_tap_ack
 *     - set TCP_WINDOW_CLAMP from TCP header from tap
 *     - check seq from header against @seq_from_tap, if data is missing, send
 *       two ACKs with number @seq_ack_to_tap, discard packet
 *     - otherwise queue data to socket, set @seq_from_tap to seq from header
 *       plus payload length
 *     - in ESTABLISHED state, send ACK to tap as soon as we queue to the
 *       socket. In other states, query socket for TCP_INFO, set
 *       @seq_ack_to_tap to (tcpi_bytes_acked + @seq_init_from_tap) % 2^32 and
 *       send ACK to tap
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
 * namespaces, the implementation is substantially simpler: packets are directly
 * translated between L4 sockets using a pair of splice() syscalls. These
 * connections are tracked in the @ts array of struct tcp_splice_conn, using
 * these states:
 *
 * - CLOSED:			no connection
 * - SPLICE_ACCEPTED:		accept() on the listening socket succeeded
 * - SPLICE_CONNECT:		connect() issued in the destination namespace
 * - SPLICE_ESTABLISHED:	connect() succeeded, packets are transferred
 * - SPLICE_FIN_FROM:		FIN (EPOLLRDHUP) seen from originating socket
 * - SPLICE_FIN_TO:		FIN (EPOLLRDHUP) seen from connected socket
 * - SPLICE_FIN_BOTH:		FIN (EPOLLRDHUP) seen from both sides
 */

#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>
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
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <time.h>

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "tap.h"
#include "siphash.h"
#include "pcap.h"
#include "conf.h"

#define MAX_TAP_CONNS			(128 * 1024)
#define MAX_SPLICE_CONNS		(128 * 1024)

#define TCP_TAP_FRAMES			32

#define RCVBUF_BIG			(2 * 1024 * 1024)
#define SNDBUF_BIG			(2 * 1024 * 1024)
#define SNDBUF_SMALL			(128 * 1024)
#define MAX_PIPE_SIZE			(2 * 1024 * 1024)

#define TCP_HASH_TABLE_LOAD		70		/* % */
#define TCP_HASH_TABLE_SIZE		(MAX_TAP_CONNS * 100 /		\
					 TCP_HASH_TABLE_LOAD)

#define MAX_WS				10
#define MAX_WINDOW			(1 << (16 + (MAX_WS)))
#define MSS_DEFAULT			536
#define WINDOW_DEFAULT			14600		/* RFC 6928 */

#define SYN_TIMEOUT			240000		/* ms */
#define ACK_TIMEOUT			2000
#define ACK_INTERVAL			50
#define ACT_TIMEOUT			7200000
#define FIN_TIMEOUT			240000
#define LAST_ACK_TIMEOUT		240000

#define TCP_SOCK_POOL_SIZE		256
#define TCP_SOCK_POOL_TSH		128 /* Refill in ns if > x used */
#define TCP_SPLICE_PIPE_POOL_SIZE	256
#define REFILL_INTERVAL			1000

#define PORT_DETECT_INTERVAL		1000

#define LOW_RTT_TABLE_SIZE		8
#define LOW_RTT_THRESHOLD		5 /* us */

/* We need to include <linux/tcp.h> for tcpi_bytes_acked, instead of
 * <netinet/tcp.h>, but that doesn't include a definition for SOL_TCP
 */
#define SOL_TCP				IPPROTO_TCP

#define SEQ_LE(a, b)			((b) - (a) < MAX_WINDOW)
#define SEQ_LT(a, b)			((b) - (a) - 1 < MAX_WINDOW)
#define SEQ_GE(a, b)			((a) - (b) < MAX_WINDOW)
#define SEQ_GT(a, b)			((a) - (b) - 1 < MAX_WINDOW)

enum tcp_state {
	CLOSED = 0,
	TAP_SYN_SENT,
	SOCK_SYN_SENT,
	TAP_SYN_RCVD,
	ESTABLISHED,
	ESTABLISHED_SOCK_FIN,
	ESTABLISHED_SOCK_FIN_SENT,
	CLOSE_WAIT,
	LAST_ACK,
	FIN_WAIT_1,
	FIN_WAIT_1_SOCK_FIN,
	SPLICE_ACCEPTED,
	SPLICE_CONNECT,
	SPLICE_ESTABLISHED,
	SPLICE_FIN_FROM,
	SPLICE_FIN_TO,
	SPLICE_FIN_BOTH,
};
#define TCP_STATE_STR_SIZE	(SPLICE_FIN_BOTH + 1)

static char *tcp_state_str[TCP_STATE_STR_SIZE] __attribute((__unused__)) = {
	"CLOSED", "TAP_SYN_SENT", "SOCK_SYN_SENT", "TAP_SYN_RCVD",
	"ESTABLISHED", "ESTABLISHED_SOCK_FIN", "ESTABLISHED_SOCK_FIN_SENT",
	"CLOSE_WAIT", "LAST_ACK", "FIN_WAIT_1", "FIN_WAIT_1_SOCK_FIN",
	"SPLICE_ACCEPTED", "SPLICE_CONNECT", "SPLICE_ESTABLISHED",
	"SPLICE_FIN_FROM", "SPLICE_FIN_TO", "SPLICE_FIN_BOTH",
};

#define FIN		(1 << 0)
#define SYN		(1 << 1)
#define RST		(1 << 2)
#define ACK		(1 << 4)
/* Flags for internal usage */
#define UPDATE_WINDOW	(1 << 5)
#define DUP_ACK		(1 << 6)
#define FORCE_ACK	(1 << 7)

#define OPT_EOL		0
#define OPT_NOP		1
#define OPT_MSS		2
#define OPT_MSS_LEN	4
#define OPT_WS		3
#define OPT_WS_LEN	3
#define OPT_SACKP	4
#define OPT_SACK	5
#define OPT_TS		8

struct tcp_tap_conn;

/**
 * struct tcp_tap_conn - Descriptor for a TCP connection via tap (not spliced)
 * @next:		Pointer to next item in hash chain, if any
 * @sock:		Socket descriptor number
 * @hash_bucket:	Bucket index in connection lookup hash table
 * @a.a6:		IPv6 remote address, can be IPv4-mapped
 * @a.a4.zero:		Zero prefix for IPv4-mapped, see RFC 6890, Table 20
 * @a.a4.one:		Ones prefix for IPv4-mapped
 * @a.a4.a:		IPv4 address
 * @tap_port:		Guest-facing tap port
 * @sock_port:		Remote, socket-facing port
 * @local:		Destination is local
 * @state:		TCP connection state
 * @seq_to_tap:		Next sequence for packets to tap
 * @seq_ack_from_tap:	Last ACK number received from tap
 * @seq_from_tap:	Next sequence for packets from tap (not actually sent)
 * @seq_ack_to_tap:	Last ACK number sent to tap
 * @seq_dup_ack:	Last duplicate ACK number sent to tap
 * @seq_init_from_tap:	Initial sequence number from tap
 * @seq_init_from_tap:	Initial sequence number to tap
 * @ws_tap:		Window scaling factor from tap
 * @ws:			Window scaling factor
 * @wnd_from_tap:	Last window size received from tap, scaled
 * @wnd_to_tap:		Socket-side sending window, advertised to tap
 * @window_clamped:	Window was clamped on socket at least once
 * @ts_sock_act:	Last activity timestamp from socket for timeout purposes
 * @ts_tap_act:		Last activity timestamp from tap for timeout purposes
 * @ts_ack_from_tap:	Last ACK segment timestamp from tap
 * @ts_ack_to_tap:	Last ACK segment timestamp to tap
 * @tap_data_noack:	Last unacked data to tap, set to { 0, 0 } on ACK
 * @mss_guest:		Maximum segment size advertised by guest
 * @events:		epoll events currently enabled for socket
 */
struct tcp_tap_conn {
	struct tcp_tap_conn *next;
	int sock;
	int hash_bucket;

	union {
		struct in6_addr a6;
		struct {
			uint8_t zero[10];
			uint8_t one[2];
			struct in_addr a;
		} a4;
	} a;
	in_port_t tap_port;
	in_port_t sock_port;
	int local;
	enum tcp_state state;

	uint32_t seq_to_tap;
	uint32_t seq_ack_from_tap;
	uint32_t seq_from_tap;
	uint32_t seq_ack_to_tap;
	uint32_t seq_dup_ack;
	uint32_t seq_init_from_tap;
	uint32_t seq_init_to_tap;

	uint16_t ws_tap;
	uint16_t ws;
	uint32_t wnd_from_tap;
	uint32_t wnd_to_tap;
	int window_clamped;
	int snd_buf;

	struct timespec ts_sock_act;
	struct timespec ts_tap_act;
	struct timespec ts_ack_from_tap;
	struct timespec ts_ack_to_tap;
	struct timespec tap_data_noack;

	int mss_guest;

	uint32_t events;
};

/**
 * struct tcp_splice_conn - Descriptor for a spliced TCP connection
 * @from:		File descriptor number of socket for accepted connection
 * @pipe_from_to:	Pipe ends for splice() from @from to @to
 * @to:			File descriptor number of peer connected socket
 * @pipe_to_from:	Pipe ends for splice() from @to to @from
 * @state:		TCP connection state
*/
struct tcp_splice_conn {
	int from;
	int pipe_from_to[2];
	int to;
	int pipe_to_from[2];
	enum tcp_state state;
	int from_fin_sent;
	int to_fin_sent;
	int v6;
	uint64_t from_read;
	uint64_t from_written;
	uint64_t to_read;
	uint64_t to_written;
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
__extension__  static struct tcp4_l2_buf_t {
	uint32_t psum;		/* 0 */
	uint32_t tsum;		/* 4 */
#ifdef __AVX2__
	uint8_t pad[18];	/* 8, align th to 32 bytes */
#endif

	uint32_t vnet_len;	/* 26 */
	struct ethhdr eh;	/* 30 */
	struct iphdr iph;	/* 44 */
	struct tcphdr th;	/* 64 */
	uint8_t data[USHRT_MAX - sizeof(struct tcphdr)];
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
tcp4_l2_buf[TCP_TAP_FRAMES] = {
	[ 0 ... TCP_TAP_FRAMES - 1 ] = {
		0, 0,
#ifdef __AVX2__
		{ 0 },
#endif
		0, L2_BUF_ETH_IP4_INIT, L2_BUF_IP4_INIT(IPPROTO_TCP),
		{ .doff = sizeof(struct tcphdr) / 4, .ack = 1 }, { 0 },
	},
};

static int tcp4_l2_buf_mss;
static int tcp4_l2_buf_mss_nr_set;
static int tcp4_l2_buf_mss_tap;
static int tcp4_l2_buf_mss_tap_nr_set;

/**
 * tcp6_l2_buf_t - Pre-cooked IPv6 packet buffers for tap connections
 * @pad:	Align IPv6 header for checksum calculation to 32B (AVX2) or 4B
 * @vnet_len:	4-byte qemu vnet buffer length descriptor, only for passt mode
 * @eh:		Pre-filled Ethernet header
 * @ip6h:	Pre-filled IP header (except for payload_len and addresses)
 * @th:		Headroom for TCP header
 * @data:	Storage for TCP payload
 */
__extension__ struct tcp6_l2_buf_t {
#ifdef __AVX2__
	uint8_t pad[14];	/* 0	align ip6h to 32 bytes */
#else
	uint8_t pad[2];		/*	align ip6h to 4 bytes	0 */
#endif
	uint32_t vnet_len;	/* 14				2 */
	struct ethhdr eh;	/* 18				6 */
	struct ipv6hdr ip6h;	/* 32				20 */
	struct tcphdr th;	/* 72				60 */
	uint8_t data[USHRT_MAX -
		     (sizeof(struct ipv6hdr) + sizeof(struct tcphdr))];
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
tcp6_l2_buf[TCP_TAP_FRAMES] = {
	[ 0 ... TCP_TAP_FRAMES - 1 ] = {
		{ 0 },
		0, L2_BUF_ETH_IP6_INIT, L2_BUF_IP6_INIT(IPPROTO_TCP),
		{ .doff = sizeof(struct tcphdr) / 4, .ack = 1 }, { 0 },
	},
};

static int tcp6_l2_buf_mss;
static int tcp6_l2_buf_mss_nr_set;
static int tcp6_l2_buf_mss_tap;
static int tcp6_l2_buf_mss_tap_nr_set;

/* recvmsg()/sendmsg() data for tap */
static struct iovec	tcp4_l2_iov_sock	[TCP_TAP_FRAMES + 1];
static struct iovec	tcp6_l2_iov_sock	[TCP_TAP_FRAMES + 1];
static char 		tcp_buf_discard		[MAX_WINDOW];

static struct iovec	tcp4_l2_iov_tap		[TCP_TAP_FRAMES];
static struct iovec	tcp6_l2_iov_tap		[TCP_TAP_FRAMES];

static struct msghdr	tcp4_l2_mh_sock;
static struct msghdr	tcp6_l2_mh_sock;

__extension__
static struct mmsghdr	tcp_l2_mh_tap		[TCP_TAP_FRAMES] = {
	[ 0 ... TCP_TAP_FRAMES - 1 ] = {
		.msg_hdr.msg_iovlen = 1,
	},
};

/* sendmsg() to socket */
static struct iovec	tcp_tap_iov		[UIO_MAXIOV];

/* SO_RCVLOWAT set on source ([0]) or destination ([1]) socket, and activity */
static uint8_t splice_rcvlowat_set[MAX_SPLICE_CONNS / 8][2];
static uint8_t splice_rcvlowat_act[MAX_SPLICE_CONNS / 8][2];

/* TCP connections */
static struct tcp_tap_conn tt[MAX_TAP_CONNS];
static struct tcp_splice_conn ts[MAX_SPLICE_CONNS];

/* Table for lookup from remote address, local port, remote port */
static struct tcp_tap_conn *tt_hash[TCP_HASH_TABLE_SIZE];

/* Pools for pre-opened sockets and pipes */
static int splice_pipe_pool	[TCP_SPLICE_PIPE_POOL_SIZE][2][2];
static int init_sock_pool4	[TCP_SOCK_POOL_SIZE];
static int init_sock_pool6	[TCP_SOCK_POOL_SIZE];
static int ns_sock_pool4	[TCP_SOCK_POOL_SIZE];
static int ns_sock_pool6	[TCP_SOCK_POOL_SIZE];

/**
 * tcp_rtt_dst_low() - Check if low RTT was seen for connection endpoint
 * @conn:	Connection pointer
 * Return: 1 if destination is in low RTT table, 0 otherwise
 */
static int tcp_rtt_dst_low(struct tcp_tap_conn *conn)
{
	int i;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++)
		if (!memcmp(&conn->a.a6, low_rtt_dst + i, sizeof(conn->a.a6)))
			return 1;

	return 0;
}

/**
 * tcp_rtt_dst_check() - Check tcpi_min_rtt, insert endpoint in table if low
 * @conn:	Connection pointer
 * @info:	Pointer to struct tcp_info for socket
 */
static void tcp_rtt_dst_check(struct tcp_tap_conn *conn, struct tcp_info *info)
{
	int i, hole = -1;

	if (!info->tcpi_min_rtt || (int)info->tcpi_min_rtt > LOW_RTT_THRESHOLD)
		return;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++) {
		if (!memcmp(&conn->a.a6, low_rtt_dst + i, sizeof(conn->a.a6)))
			return;
		if (hole == -1 && IN6_IS_ADDR_UNSPECIFIED(low_rtt_dst + i))
			hole = i;
	}

	memcpy(low_rtt_dst + hole++, &conn->a.a6, sizeof(conn->a.a6));
	if (hole == LOW_RTT_TABLE_SIZE)
		hole = 0;
	memcpy(low_rtt_dst + hole, &in6addr_any, sizeof(conn->a.a6));
}

/**
 * tcp_tap_state() - Set given TCP state for tap connection, report to stderr
 * @conn:	Connection pointer
 * @state:	New TCP state to be set
 */
static void tcp_tap_state(struct tcp_tap_conn *conn, enum tcp_state state)
{
	debug("TCP: socket %i: %s -> %s",
	      conn->sock, tcp_state_str[conn->state], tcp_state_str[state]);
	conn->state = state;
}

/**
 * tcp_splice_state() - Set state for spliced connection, report to stderr
 * @conn:	Connection pointer
 * @state:	New TCP state to be set
 */
static void tcp_splice_state(struct tcp_splice_conn *conn, enum tcp_state state)
{
	debug("TCP: index %i: %s -> %s",
	      conn - ts, tcp_state_str[conn->state], tcp_state_str[state]);
	conn->state = state;
}

/**
 * tcp_probe_mem() - Check if setting high SO_SNDBUF and SO_RCVBUF is allowed
 * @c:		Execution context
 */
static void tcp_probe_mem(struct ctx *c)
{
	int v = INT_MAX / 2, s;
	socklen_t sl;

	if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		c->tcp.low_wmem = c->tcp.low_rmem = 1;
		return;
	}

	sl = sizeof(v);
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v))	||
	    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, &sl) || v < SNDBUF_BIG)
		c->tcp.low_wmem = 1;

	v = INT_MAX / 2;
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v))	||
	    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &sl) || v < RCVBUF_BIG)
		c->tcp.low_rmem = 1;

	close(s);
}

/**
 * tcp_get_sndbuf() - Get, scale SO_SNDBUF between thresholds (1 to 0.5 usage)
 * @conn:	Connection pointer
 */
static void tcp_get_sndbuf(struct tcp_tap_conn *conn)
{
	int s = conn->sock, v;
	socklen_t sl;

	sl = sizeof(v);
	if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, &sl)) {
		conn->snd_buf = WINDOW_DEFAULT;
		return;
	}

	if (v >= SNDBUF_BIG)
		v /= 2;
	else if (v > SNDBUF_SMALL)
		v -= v * (v - SNDBUF_SMALL) / (SNDBUF_BIG - SNDBUF_SMALL) / 2;

	conn->snd_buf = v;
}

/**
 * tcp_sock_set_bufsize() - Set SO_RCVBUF and SO_SNDBUF to maximum values
 * @s:		Socket, can be -1 to avoid check in the caller
 */
static void tcp_sock_set_bufsize(struct ctx *c, int s)
{
	int v = INT_MAX / 2; /* Kernel clamps and rounds, no need to check */

	if (s == -1)
		return;

	if (!c->tcp.low_rmem)
		setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v));

	if (!c->tcp.low_wmem)
		setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v));
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
void tcp_update_l2_buf(unsigned char *eth_d, unsigned char *eth_s,
		       uint32_t *ip_da)
{
	int i;

	for (i = 0; i < TCP_TAP_FRAMES; i++) {
		struct tcp4_l2_buf_t *b4 = &tcp4_l2_buf[i];
		struct tcp6_l2_buf_t *b6 = &tcp6_l2_buf[i];

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

				b4->tsum = ((*ip_da >> 16) & 0xffff) +
					   (*ip_da & 0xffff) +
					   htons(IPPROTO_TCP);
			} else {
				b4->psum = tcp4_l2_buf[0].psum;
				b4->tsum = tcp4_l2_buf[0].tsum;
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

	tcp4_l2_iov_sock[0].iov_base = tcp_buf_discard;
	for (i = 0, iov = tcp4_l2_iov_sock + 1; i < TCP_TAP_FRAMES;
	     i++, iov++) {
		iov->iov_base = &tcp4_l2_buf[i].data;
		iov->iov_len = MSS_DEFAULT;
	}

	tcp4_l2_mh_sock.msg_iov = tcp4_l2_iov_sock;

	for (i = 0, iov = tcp4_l2_iov_tap; i < TCP_TAP_FRAMES; i++, iov++) {
		iov->iov_base = &tcp4_l2_buf[i].vnet_len;
		iov->iov_len = MSS_DEFAULT;
	}
}

/**
 * tcp_sock6_iov_init() - Initialise scatter-gather L2 buffers for IPv6 sockets
 */
static void tcp_sock6_iov_init(void)
{
	struct iovec *iov;
	int i;

	tcp6_l2_iov_sock[0].iov_base = tcp_buf_discard;
	for (i = 0, iov = tcp6_l2_iov_sock + 1; i < TCP_TAP_FRAMES;
	     i++, iov++) {
		iov->iov_base = &tcp6_l2_buf[i].data;
		iov->iov_len = MSS_DEFAULT;
	}

	tcp6_l2_mh_sock.msg_iov = tcp6_l2_iov_sock;

	for (i = 0, iov = tcp6_l2_iov_tap; i < TCP_TAP_FRAMES; i++, iov++) {
		iov->iov_base = &tcp6_l2_buf[i].vnet_len;
		iov->iov_len = MSS_DEFAULT;
	}
}

/**
 * tcp_opt_get() - Get option, and value if any, from TCP header
 * @th:		Pointer to TCP header
 * @len:	Length of buffer, including TCP header
 * @__type:	Option type to look for
 * @__optlen:	Optional, filled with option length if passed
 * @__value:	Optional, set to start of option value if passed
 *
 * Return: Option value, meaningful for up to 4 bytes, -1 if not found
 */
static int tcp_opt_get(struct tcphdr *th, size_t len, uint8_t __type,
		       uint8_t *__optlen, char **__value)
{
	uint8_t type, optlen;
	char *p;

	if (len > th->doff * 4)
		len = th->doff * 4;

	len -= sizeof(*th);
	p = (char *)(th + 1);

	for (; len >= 2; p += optlen, len -= optlen) {
		switch (*p) {
		case OPT_EOL:
			return -1;
		case OPT_NOP:
			optlen = 1;
			break;
		default:
			type = *(p++);
			optlen = *(p++) - 2;
			len -= 2;

			if (type != __type)
				break;

			if (__optlen)
				*__optlen = optlen;
			if (__value)
				*__value = p;

			switch (optlen) {
			case 0:
				return 0;
			case 1:
				return *p;
			case 2:
				return ntohs(*(uint16_t *)p);
			default:
				return ntohl(*(uint32_t *)p);
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
static int tcp_hash_match(struct tcp_tap_conn *conn, int af, void *addr,
			  in_port_t tap_port, in_port_t sock_port)
{
	if (af == AF_INET && IN6_IS_ADDR_V4MAPPED(&conn->a.a6)	&&
	    !memcmp(&conn->a.a4.a, addr, sizeof(conn->a.a4.a))	&&
	    conn->tap_port == tap_port && conn->sock_port == sock_port)
		return 1;

	if (af == AF_INET6					&&
	    !memcmp(&conn->a.a6, addr, sizeof(conn->a.a6))	&&
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
static unsigned int tcp_hash(struct ctx *c, int af, void *addr,
			     in_port_t tap_port, in_port_t sock_port)
{
	uint64_t b = 0;

	if (af == AF_INET) {
		struct {
			struct in_addr addr;
			in_port_t tap_port;
			in_port_t sock_port;
		} __attribute__((__packed__)) in = {
			.addr = *(struct in_addr *)addr,
			.tap_port = tap_port,
			.sock_port = sock_port,
		};

		b = siphash_8b((uint8_t *)&in, c->tcp.hash_secret);
	} else if (af == AF_INET6) {
		struct {
			struct in6_addr addr;
			in_port_t tap_port;
			in_port_t sock_port;
		} __attribute__((__packed__)) in = {
			.addr = *(struct in6_addr *)addr,
			.tap_port = tap_port,
			.sock_port = sock_port,
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
static void tcp_hash_insert(struct ctx *c, struct tcp_tap_conn *conn,
			    int af, void *addr)
{
	int b;

	b = tcp_hash(c, af, addr, conn->tap_port, conn->sock_port);
	conn->next = tt_hash[b];
	tt_hash[b] = conn;
	conn->hash_bucket = b;

	debug("TCP: hash table insert: index %i, sock %i, bucket: %i, next: %p",
	      conn - tt, conn->sock, b, conn->next);
}

/**
 * tcp_hash_remove() - Drop connection from hash table, chain unlink
 * @conn:	Connection pointer
 */
static void tcp_hash_remove(struct tcp_tap_conn *conn)
{
	struct tcp_tap_conn *entry, *prev = NULL;
	int b = conn->hash_bucket;

	for (entry = tt_hash[b]; entry; prev = entry, entry = entry->next) {
		if (entry == conn) {
			if (prev)
				prev->next = conn->next;
			else
				tt_hash[b] = conn->next;
			break;
		}
	}

	debug("TCP: hash table remove: index %i, sock %i, bucket: %i, new: %p",
	      conn - tt, conn->sock, b, prev ? prev->next : tt_hash[b]);
}

/**
 * tcp_hash_update() - Update pointer for given connection
 * @old:	Old connection pointer
 * @new:	New connection pointer
 */
static void tcp_hash_update(struct tcp_tap_conn *old, struct tcp_tap_conn *new)
{
	struct tcp_tap_conn *entry, *prev = NULL;
	int b = old->hash_bucket;

	for (entry = tt_hash[b]; entry; prev = entry, entry = entry->next) {
		if (entry == old) {
			if (prev)
				prev->next = new;
			else
				tt_hash[b] = new;
			break;
		}
	}

	debug("TCP: hash table update: old index %i, new index %i, sock %i, "
	      "bucket: %i, old: %p, new: %p",
	      old - tt, new - tt, new->sock, b, old, new);
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
static struct tcp_tap_conn *tcp_hash_lookup(struct ctx *c, int af, void *addr,
					    in_port_t tap_port,
					    in_port_t sock_port)
{
	int b = tcp_hash(c, af, addr, tap_port, sock_port);
	struct tcp_tap_conn *conn;

	for (conn = tt_hash[b]; conn; conn = conn->next) {
		if (tcp_hash_match(conn, af, addr, tap_port, sock_port))
			return conn;
	}

	return NULL;
}

/**
 * tcp_tap_epoll_mask() - Set new epoll event mask given a connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @events:	New epoll event bitmap
 */
static void tcp_tap_epoll_mask(struct ctx *c, struct tcp_tap_conn *conn,
			       uint32_t events)
{
	union epoll_ref ref = { .proto = IPPROTO_TCP, .s = conn->sock,
				.tcp.index = conn - tt,
				.tcp.v6 = !IN6_IS_ADDR_V4MAPPED(&conn->a.a6) };
	struct epoll_event ev = { .data.u64 = ref.u64, .events = events };

	if (conn->events == events)
		return;

	conn->events = events;
	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->sock, &ev);
}

/**
 * tcp_table_tap_compact() - Perform compaction on tap connection table
 * @c:		Execution context
 * @hole:	Pointer to recently closed connection
 */
static void tcp_table_tap_compact(struct ctx *c, struct tcp_tap_conn *hole)
{
	struct tcp_tap_conn *from, *to;
	uint32_t events;

	if ((hole - tt) == --c->tcp.tap_conn_count) {
		debug("TCP: hash table compaction: index %i (%p) was max index",
		      hole - tt, hole);
		return;
	}

	from = &tt[c->tcp.tap_conn_count];
	memcpy(hole, from, sizeof(*hole));
	from->state = CLOSED;

	to = hole;
	tcp_hash_update(from, to);

	events = hole->events;
	hole->events = UINT_MAX;
	tcp_tap_epoll_mask(c, hole, events);

	debug("TCP: hash table compaction: old index %i, new index %i, "
	      "sock %i, from: %p, to: %p",
	      from - tt, to - tt, from->sock, from, to);
}

/**
 * tcp_tap_destroy() - Close tap connection, drop from hash table and epoll
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_tap_destroy(struct ctx *c, struct tcp_tap_conn *conn)
{
	if (conn->state == CLOSED)
		return;

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->sock, NULL);
	tcp_tap_state(conn, CLOSED);
	close(conn->sock);

	/* Removal from hash table and connection table compaction deferred to
	 * timer.
	 */
}

static void tcp_rst(struct ctx *c, struct tcp_tap_conn *conn);

/**
 * tcp_send_to_tap() - Send segment to tap, with options and values from socket
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags to set
 * @now:	Current timestamp, can be NULL
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
static int tcp_send_to_tap(struct ctx *c, struct tcp_tap_conn *conn, int flags,
			   struct timespec *now)
{
	char buf[sizeof(struct tcphdr) + OPT_MSS_LEN + OPT_WS_LEN + 1] = { 0 };
	uint32_t prev_ack_to_tap = conn->seq_ack_to_tap;
	struct tcp_info info = { 0 };
	socklen_t sl = sizeof(info);
	int s = conn->sock;
	struct tcphdr *th;
	char *data;

	if (SEQ_GE(conn->seq_ack_to_tap, conn->seq_from_tap) &&
	    !flags && conn->wnd_to_tap)
		return 0;

	if (conn->snd_buf < SNDBUF_SMALL)
		tcp_get_sndbuf(c, conn);

	if (getsockopt(s, SOL_TCP, TCP_INFO, &info, &sl)) {
		tcp_rst(c, conn);
		return -ECONNRESET;
	}

	th = (struct tcphdr *)buf;
	data = (char *)(th + 1);
	th->doff = sizeof(*th) / 4;

	if (flags & SYN) {
		uint16_t mss;

		/* Options: MSS, NOP and window scale if allowed (4-8 bytes) */
		*data++ = OPT_MSS;
		*data++ = OPT_MSS_LEN;

		if (c->mtu == -1) {
			mss = info.tcpi_snd_mss;
		} else {
			mss = c->mtu - sizeof(sizeof *th);
			if (IN6_IS_ADDR_V4MAPPED(&conn->a.a6))
				mss -= sizeof(struct iphdr);
			else
				mss -= sizeof(struct ipv6hdr);

			if (c->tcp.low_wmem &&
			    !conn->local && !tcp_rtt_dst_low(conn))
				mss = MIN(mss, PAGE_SIZE);
			else
				mss = ROUND_DOWN(mss, PAGE_SIZE);
		}
		*(uint16_t *)data = htons(mss);

		data += OPT_MSS_LEN - 2;
		th->doff += OPT_MSS_LEN / 4;

		if (!c->tcp.kernel_snd_wnd && info.tcpi_snd_wnd)
			c->tcp.kernel_snd_wnd = 1;

		conn->ws = MIN(MAX_WS, info.tcpi_snd_wscale);

		*data++ = OPT_NOP;
		*data++ = OPT_WS;
		*data++ = OPT_WS_LEN;
		*data++ = conn->ws;
		th->doff += (1 + OPT_WS_LEN) / 4;

		/* RFC 793, 3.1: "[...] and the first data octet is ISN+1." */
		th->seq = htonl(conn->seq_to_tap++);

		th->ack = !!(flags & ACK);
	} else {
		th->ack = 1;
		th->seq = htonl(conn->seq_to_tap);
	}

	if (conn->state > ESTABLISHED || (flags & (DUP_ACK | FORCE_ACK))) {
		conn->seq_ack_to_tap = conn->seq_from_tap;
	} else {
		conn->seq_ack_to_tap = info.tcpi_bytes_acked +
				       conn->seq_init_from_tap;

		if (SEQ_LT(conn->seq_ack_to_tap, prev_ack_to_tap))
			conn->seq_ack_to_tap = prev_ack_to_tap;
	}

	if (!flags &&
	    conn->seq_ack_to_tap == prev_ack_to_tap &&
	    c->tcp.kernel_snd_wnd && conn->wnd_to_tap == info.tcpi_snd_wnd)
		return 0;

	th->ack_seq = htonl(conn->seq_ack_to_tap);

	th->rst = !!(flags & RST);
	th->syn = !!(flags & SYN);
	th->fin = !!(flags & FIN);

	th->source = htons(conn->sock_port);
	th->dest = htons(conn->tap_port);

	if (th->syn) {
		/* First value sent by receiver is not scaled */
		th->window = htons(conn->wnd_to_tap = WINDOW_DEFAULT);
	} else {
		if (c->tcp.kernel_snd_wnd) {
			conn->wnd_to_tap = MIN(info.tcpi_snd_wnd,
					       conn->snd_buf);
		} else {
			conn->wnd_to_tap = conn->snd_buf;
		}
		conn->wnd_to_tap = MIN(conn->wnd_to_tap, MAX_WINDOW);

		th->window = htons(MIN(conn->wnd_to_tap >> conn->ws,
				       USHRT_MAX));
	}

	th->urg_ptr = 0;
	th->check = 0;

	if (th->ack && now)
		conn->ts_ack_to_tap = *now;

	tap_ip_send(c, &conn->a.a6, IPPROTO_TCP, buf, th->doff * 4,
		    conn->seq_init_to_tap);

	if (flags & DUP_ACK) {
		tap_ip_send(c, &conn->a.a6, IPPROTO_TCP, buf, th->doff * 4,
			    conn->seq_init_to_tap);
	}

	if (th->fin) {
		conn->tap_data_noack = *now;
		conn->seq_to_tap++;
	}

	return 0;
}

/**
 * tcp_rst() - Reset a tap connection: send RST segment to tap, close socket
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_rst(struct ctx *c, struct tcp_tap_conn *conn)
{
	if (conn->state == CLOSED)
		return;

	tcp_send_to_tap(c, conn, RST, NULL);
	tcp_tap_destroy(c, conn);
}

/**
 * tcp_clamp_window() - Set window and scaling from option, clamp on socket
 * @conn:	Connection pointer
 * @th:		TCP header, from tap, can be NULL if window is passed
 * @len:	Buffer length, at L4, can be 0 if no header is passed
 * @window:	Window value, host order, unscaled, if no header is passed
 * @init:	Set if this is the very first segment from tap
 */
static void tcp_clamp_window(struct tcp_tap_conn *conn, struct tcphdr *th,
			     int len, unsigned int window, int init)
{
	if (init) {
		int ws = tcp_opt_get(th, len, OPT_WS, NULL, NULL);

		conn->ws_tap = ws;

		/* RFC 7323, 2.2: first value is not scaled. Also, don't clamp
		 * yet, to avoid getting a zero scale just because we set a
		 * small window now.
		 */
		conn->wnd_from_tap = ntohs(th->window);
		conn->window_clamped = 0;
	} else {
		if (th)
			window = ntohs(th->window) << conn->ws_tap;
		else
			window <<= conn->ws_tap;

		window = MIN(MAX_WINDOW, window);

		if (conn->window_clamped) {
			if (conn->wnd_from_tap == window)
				return;

			/* Discard +/- 1% updates to spare some syscalls. */
			if ((window > conn->wnd_from_tap &&
			     window * 99 / 100 < conn->wnd_from_tap) ||
			    (window < conn->wnd_from_tap &&
			     window * 101 / 100 > conn->wnd_from_tap)) {
				conn->wnd_from_tap = window;
				return;
			}
		}

		conn->wnd_from_tap = window;
		if (window < 256)
			window = 256;
		setsockopt(conn->sock, SOL_TCP, TCP_WINDOW_CLAMP,
			   &window, sizeof(window));
		conn->window_clamped = 1;
	}
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
static uint32_t tcp_seq_init(struct ctx *c, int af, void *addr,
			     in_port_t dstport, in_port_t srcport,
			     struct timespec *now)
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
			.dst = { c->addr4 },
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
			.dst = c->addr6,
			.dstport = dstport,
		};

		seq = siphash_36b((uint8_t *)&in, c->tcp.hash_secret);
	}

	ns = now->tv_sec * 1E9;
	ns += now->tv_nsec >> 5; /* 32ns ticks, overflows 32 bits every 137s */

	return seq + ns;
}

/**
 * tcp_conn_from_tap() - Handle connection request (SYN segment) from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @th:		TCP header from tap
 * @len:	Packet length at L4
 * @now:	Current timestamp
 */
static void tcp_conn_from_tap(struct ctx *c, int af, void *addr,
			      struct tcphdr *th, size_t len,
			      struct timespec *now)
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
	union epoll_ref ref = { .proto = IPPROTO_TCP };
	const struct sockaddr *sa;
	struct tcp_tap_conn *conn;
	int i, s, *sock_pool_p;
	struct epoll_event ev;
	socklen_t sl;

	if (c->tcp.tap_conn_count >= MAX_TAP_CONNS)
		return;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++) {
		if (af == AF_INET6)
			sock_pool_p = &init_sock_pool6[i];
		else
			sock_pool_p = &init_sock_pool4[i];
		if ((ref.s = s = *sock_pool_p) > 0) {
			*sock_pool_p = -1;
			break;
		}
	}

	if (s < 0)
		ref.s = s = socket(af, SOCK_STREAM | SOCK_NONBLOCK,
				   IPPROTO_TCP);

	if (s < 0)
		return;

	tcp_sock_set_bufsize(c, s);

	if (af == AF_INET && addr4.sin_addr.s_addr == c->gw4)
		addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else if (af == AF_INET6 && !memcmp(addr, &c->gw6, sizeof(c->gw6)))
		addr6.sin6_addr = in6addr_loopback;

	if (af == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr6.sin6_addr)) {
		struct sockaddr_in6 addr6_ll = {
			.sin6_family = AF_INET6,
			.sin6_addr = c->addr6_ll,
			.sin6_scope_id = if_nametoindex(c->ifn),
		};
		bind(s, (struct sockaddr *)&addr6_ll, sizeof(addr6_ll));
	}

	conn = &tt[c->tcp.tap_conn_count++];
	conn->sock = s;
	conn->events = 0;

	conn->wnd_to_tap = WINDOW_DEFAULT;

	conn->mss_guest = tcp_opt_get(th, len, OPT_MSS, NULL, NULL);
	if (conn->mss_guest < 0)
		conn->mss_guest = MSS_DEFAULT;

	if (c->mode == MODE_PASST) {
		/* Don't upset qemu */
		conn->mss_guest = MIN(USHRT_MAX -
				      sizeof(uint32_t) -
				      sizeof(struct ethhdr) -
				      sizeof(struct ipv6hdr) -
				      sizeof(struct tcphdr),
				      conn->mss_guest);
	}

	sl = sizeof(conn->mss_guest);
	setsockopt(s, SOL_TCP, TCP_MAXSEG, &conn->mss_guest, sl);

	tcp_clamp_window(conn, th, len, 0, 1);

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

	conn->ts_sock_act = conn->ts_tap_act = *now;
	conn->ts_ack_to_tap = conn->ts_ack_from_tap = *now;

	conn->seq_init_from_tap = ntohl(th->seq);
	conn->seq_from_tap = conn->seq_init_from_tap + 1;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	conn->seq_to_tap = tcp_seq_init(c, af, addr, th->dest, th->source, now);
	conn->seq_init_to_tap = conn->seq_to_tap;
	conn->seq_ack_from_tap = conn->seq_to_tap + 1;

	tcp_hash_insert(c, conn, af, addr);

	if (!bind(s, sa, sl))
		tcp_rst(c, conn);	/* Nobody is listening then */
	if (errno != EADDRNOTAVAIL)
		conn->local = 1;

	if (connect(s, sa, sl)) {
		tcp_tap_state(conn, TAP_SYN_SENT);

		if (errno != EINPROGRESS) {
			tcp_rst(c, conn);
			return;
		}

		ev.events = EPOLLOUT | EPOLLRDHUP;

		tcp_get_sndbuf(conn);
	} else {
		tcp_tap_state(conn, TAP_SYN_RCVD);

		tcp_get_sndbuf(conn);

		if (tcp_send_to_tap(c, conn, SYN | ACK, now))
			return;

		ev.events = EPOLLIN | EPOLLRDHUP;
	}

	conn->events = ev.events;
	ref.tcp.index = conn - tt;
	ev.data.u64 = ref.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, s, &ev);
}

/**
 * tcp_table_splice_compact - Compact spliced connection table
 * @c:		Execution context
 * @hole:	Pointer to recently closed connection
 */
static void tcp_table_splice_compact(struct ctx *c,
				     struct tcp_splice_conn *hole)
{
	union epoll_ref ref_from = { .proto = IPPROTO_TCP, .tcp.splice = 1,
				     .tcp.index = hole - ts };
	union epoll_ref ref_to = { .proto = IPPROTO_TCP, .tcp.splice = 1,
				   .tcp.index = hole - ts };
	struct tcp_splice_conn *move;
	struct epoll_event ev_from;
	struct epoll_event ev_to;

	hole->from_fin_sent = hole->to_fin_sent = 0;
	hole->from_read = hole->from_written = 0;
	hole->to_read = hole->to_written = 0;

	bitmap_clear(splice_rcvlowat_set[0], hole - ts);
	bitmap_clear(splice_rcvlowat_set[1], hole - ts);
	bitmap_clear(splice_rcvlowat_act[0], hole - ts);
	bitmap_clear(splice_rcvlowat_act[1], hole - ts);

	if ((hole - ts) == --c->tcp.splice_conn_count)
		return;

	move = &ts[c->tcp.splice_conn_count];
	if (move->state == CLOSED)
		return;

	memcpy(hole, move, sizeof(*hole));
	move->state = CLOSED;
	move = hole;

	ref_from.s = move->from;
	ref_from.tcp.v6 = move->v6;
	ref_to.s = move->to;
	ref_to.tcp.v6 = move->v6;

	if (move->state == SPLICE_ACCEPTED) {
		ev_from.events = ev_to.events = 0;
	} else if (move->state == SPLICE_CONNECT) {
		ev_from.events = 0;
		ev_to.events = EPOLLOUT;
	} else {
		ev_from.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
		ev_to.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
	}

	ev_from.data.u64 = ref_from.u64;
	ev_to.data.u64 = ref_to.u64;

	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, move->from, &ev_from);
	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, move->to, &ev_to);
}

/**
 * tcp_splice_destroy() - Close spliced connection and pipes, drop from epoll
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_splice_destroy(struct ctx *c, struct tcp_splice_conn *conn)
{
	int epoll_del_done = 0;

	switch (conn->state) {
	case CLOSED:
		epoll_del_done = 1;
		/* Falls through */
	case SPLICE_FIN_BOTH:
	case SPLICE_FIN_FROM:
	case SPLICE_FIN_TO:
	case SPLICE_ESTABLISHED:
		/* Flushing might need to block: don't recycle them. */
		if (conn->pipe_from_to[0] != -1) {
			close(conn->pipe_from_to[0]);
			conn->pipe_from_to[0] = -1;
			close(conn->pipe_from_to[1]);
			conn->pipe_from_to[1] = -1;
		}
		if (conn->pipe_to_from[0] != -1) {
			close(conn->pipe_to_from[0]);
			conn->pipe_to_from[0] = -1;
			close(conn->pipe_to_from[1]);
			conn->pipe_to_from[1] = -1;
		}
		/* Falls through */
	case SPLICE_CONNECT:
		if (!epoll_del_done) {
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->from, NULL);
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->to, NULL);
		}
		close(conn->to);
		/* Falls through */
	case SPLICE_ACCEPTED:
		close(conn->from);
		tcp_splice_state(conn, CLOSED);
		tcp_table_splice_compact(c, conn);
		break;
	default:
		return;
	}
}

/**
 * tcp_sock_consume() - Consume (discard) data from buffer, update ACK sequence
 * @conn:	Connection pointer
 * @ack_seq:	ACK sequence, host order
 */
static void tcp_sock_consume(struct tcp_tap_conn *conn, uint32_t ack_seq)
{
	/* Simply ignore out-of-order ACKs: we already consumed the data we
	 * needed from the buffer, and we won't rewind back to a lower ACK
	 * sequence.
	 */
	if (SEQ_LE(ack_seq, conn->seq_ack_from_tap))
		return;

	recv(conn->sock, NULL, ack_seq - conn->seq_ack_from_tap,
	     MSG_DONTWAIT | MSG_TRUNC);

	conn->seq_ack_from_tap = ack_seq;
}

/**
 * tcp_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @conn:	Connection pointer
 * @now:	Current timestamp
 *
 * Return: negative on connection reset, 0 otherwise
 */
static int tcp_data_from_sock(struct ctx *c, struct tcp_tap_conn *conn,
			      struct timespec *now)
{
	int *buf_mss, *buf_mss_nr_set, *buf_mss_tap, *buf_mss_tap_nr_set;
	int mss_tap, fill_bufs, send_bufs = 0, last_len, iov_rem = 0;
	int send, len, plen, v4 = IN6_IS_ADDR_V4MAPPED(&conn->a.a6);
	uint32_t seq_to_tap = conn->seq_to_tap;
	socklen_t sl = sizeof(struct tcp_info);
	int s = conn->sock, i, ret = 0;
	struct iovec *iov, *iov_tap;
	uint32_t already_sent;
	struct tcp_info info;
	struct mmsghdr *mh;

	already_sent = conn->seq_to_tap - conn->seq_ack_from_tap;

	if (SEQ_LT(already_sent, 0)) {
		/* RFC 761, section 2.1. */
		seq_to_tap = conn->seq_to_tap = conn->seq_ack_from_tap;
		already_sent = 0;
	}

	if (!conn->wnd_from_tap || already_sent >= conn->wnd_from_tap) {
		tcp_tap_epoll_mask(c, conn, conn->events | EPOLLET);
		return 0;
	}

	fill_bufs = DIV_ROUND_UP(conn->wnd_from_tap - already_sent,
				 conn->mss_guest);
	if (fill_bufs > TCP_TAP_FRAMES) {
		fill_bufs = TCP_TAP_FRAMES;
		iov_rem = 0;
	} else {
		iov_rem = (conn->wnd_from_tap - already_sent) % conn->mss_guest;
	}

	/* Adjust iovec length for recvmsg() based on what was set last time. */
	if (v4) {
		iov = tcp4_l2_iov_sock + 1;
		buf_mss = &tcp4_l2_buf_mss;
		buf_mss_nr_set = &tcp4_l2_buf_mss_nr_set;
	} else {
		iov = tcp6_l2_iov_sock + 1;
		buf_mss = &tcp6_l2_buf_mss;
		buf_mss_nr_set = &tcp6_l2_buf_mss_nr_set;
	}
	if (*buf_mss != conn->mss_guest)
		*buf_mss_nr_set = 0;
	for (i = *buf_mss_nr_set; i < fill_bufs; i++)
		iov[i].iov_len = conn->mss_guest;
	*buf_mss = conn->mss_guest;
	*buf_mss_nr_set = fill_bufs - 1;

	/* First buffer is to discard data, last one may be partially filled. */
	iov[-1].iov_len = already_sent;
	if (iov_rem)
		iov[fill_bufs - 1].iov_len = iov_rem;
	if (v4)
		tcp4_l2_mh_sock.msg_iovlen = fill_bufs + 1;
	else
		tcp6_l2_mh_sock.msg_iovlen = fill_bufs + 1;

	/* Don't dequeue until acknowledged by guest. */
recvmsg:
	len = recvmsg(s, v4 ? &tcp4_l2_mh_sock : &tcp6_l2_mh_sock, MSG_PEEK);
	if (len < 0) {
		if (errno == EINTR)
			goto recvmsg;
		goto err;
	}

	if (!len)
		goto zero_len;

	send = len - already_sent;
	if (send <= 0) {
		tcp_tap_epoll_mask(c, conn, conn->events | EPOLLET);
		goto out;
	}

	tcp_tap_epoll_mask(c, conn, conn->events & ~EPOLLET);

	send_bufs = DIV_ROUND_UP(send, conn->mss_guest);
	last_len = send - (send_bufs - 1) * conn->mss_guest;

	/* Adjust iovec length for sending based on what was set last time. */
	if (v4) {
		mss_tap = conn->mss_guest +
			  offsetof(struct tcp4_l2_buf_t, data) -
			  offsetof(struct tcp4_l2_buf_t, vnet_len);

		iov_tap = tcp4_l2_iov_tap;
		buf_mss_tap = &tcp4_l2_buf_mss_tap;
		buf_mss_tap_nr_set = &tcp4_l2_buf_mss_tap_nr_set;
	} else {
		mss_tap = conn->mss_guest +
			  offsetof(struct tcp6_l2_buf_t, data) -
			  offsetof(struct tcp6_l2_buf_t, vnet_len);

		iov_tap = tcp6_l2_iov_tap;
		buf_mss_tap = &tcp6_l2_buf_mss_tap;
		buf_mss_tap_nr_set = &tcp6_l2_buf_mss_tap_nr_set;
	}
	if (*buf_mss_tap != mss_tap)
		*buf_mss_tap_nr_set = 0;
	for (i = *buf_mss_tap_nr_set; i < send_bufs; i++)
		iov_tap[i].iov_len = mss_tap;
	*buf_mss_tap = mss_tap;
	*buf_mss_tap_nr_set = send_bufs;

	iov_tap[send_bufs - 1].iov_len = mss_tap - conn->mss_guest + last_len;

	/* Likely, some new data was acked too. */
	if (conn->seq_from_tap != conn->seq_ack_to_tap || !conn->wnd_to_tap) {
		if (conn->state != ESTABLISHED ||
		    getsockopt(s, SOL_TCP, TCP_INFO, &info, &sl)) {
			conn->seq_ack_to_tap = conn->seq_from_tap;
		} else {
			conn->seq_ack_to_tap = info.tcpi_bytes_acked +
					       conn->seq_init_from_tap;

			if (c->tcp.kernel_snd_wnd) {
				conn->wnd_to_tap = MIN(info.tcpi_snd_wnd,
						       conn->snd_buf);
			} else {
				conn->wnd_to_tap = conn->snd_buf;
			}
			conn->wnd_to_tap = MIN(conn->wnd_to_tap, MAX_WINDOW);
		}
	}

	plen = conn->mss_guest;
	for (i = 0, mh = tcp_l2_mh_tap; i < send_bufs; i++, mh++) {
		int ip_len;

		if (i == send_bufs - 1)
			plen = last_len;

		if (v4) {
			struct tcp4_l2_buf_t *b = &tcp4_l2_buf[i];

			ip_len = plen + sizeof(struct iphdr) +
				 sizeof(struct tcphdr);

			b->iph.tot_len = htons(ip_len);
			b->iph.saddr = conn->a.a4.a.s_addr;
			b->iph.daddr = c->addr4_seen;
			if (!i || i == send_bufs - 1)
				tcp_update_check_ip4(b);
			else
				b->iph.check = tcp4_l2_buf[0].iph.check;

			b->th.source = htons(conn->sock_port);
			b->th.dest = htons(conn->tap_port);
			b->th.seq = htonl(seq_to_tap);
			b->th.ack_seq = htonl(conn->seq_ack_to_tap);
			b->th.window = htons(MIN(conn->wnd_to_tap >> conn->ws,
						 USHRT_MAX));

			tcp_update_check_tcp4(b);

			if (c->mode == MODE_PASST) {
				b->vnet_len = htonl(sizeof(struct ethhdr) +
						    ip_len);
				mh->msg_hdr.msg_iov = &tcp4_l2_iov_tap[i];
				seq_to_tap += plen;
				continue;
			}

			ip_len += sizeof(struct ethhdr);
			pcap((char *)&b->eh, ip_len);
			ret = write(c->fd_tap, &b->eh, ip_len);
		} else {
			struct tcp6_l2_buf_t *b = &tcp6_l2_buf[i];
			uint32_t flow = conn->seq_init_to_tap;

			ip_len = plen + sizeof(struct ipv6hdr) +
				 sizeof(struct tcphdr);

			b->ip6h.payload_len = htons(plen +
						    sizeof(struct tcphdr));
			b->ip6h.saddr = conn->a.a6;
			if (IN6_IS_ADDR_LINKLOCAL(&b->ip6h.saddr))
				b->ip6h.daddr = c->addr6_ll_seen;
			else
				b->ip6h.daddr = c->addr6_seen;

			b->th.source = htons(conn->sock_port);
			b->th.dest = htons(conn->tap_port);
			b->th.seq = htonl(seq_to_tap);
			b->th.ack_seq = htonl(conn->seq_ack_to_tap);
			b->th.window = htons(MIN(conn->wnd_to_tap >> conn->ws,
						 USHRT_MAX));

			memset(b->ip6h.flow_lbl, 0, 3);
			tcp_update_check_tcp6(b);

			b->ip6h.flow_lbl[0] = (flow >> 16) & 0xf;
			b->ip6h.flow_lbl[1] = (flow >> 8) & 0xff;
			b->ip6h.flow_lbl[2] = (flow >> 0) & 0xff;

			if (c->mode == MODE_PASST) {
				b->vnet_len = htonl(sizeof(struct ethhdr) +
						    ip_len);
				mh->msg_hdr.msg_iov = &tcp6_l2_iov_tap[i];
				seq_to_tap += plen;
				continue;
			}

			ip_len += sizeof(struct ethhdr);
			pcap((char *)&b->eh, ip_len);
			ret = write(c->fd_tap, &b->eh, ip_len);
		}

		if (ret < ip_len) {
			if (ret < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return 0;

				tap_handler(c, EPOLLERR, now);
			}

			i--;
			continue;
		}

		conn->seq_to_tap += plen;
	}

	if (c->mode == MODE_PASTA)
		goto out;

sendmmsg:
	ret = sendmmsg(c->fd_tap, tcp_l2_mh_tap, mh - tcp_l2_mh_tap,
		       MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret < 0 && errno == EINTR)
		goto sendmmsg;

	if (ret <= 0)
		goto out;

	conn->tap_data_noack = *now;
	conn->seq_to_tap += conn->mss_guest * (ret - 1) + last_len;

	/* sendmmsg() indicates how many messages were sent at least partially.
	 * Kernel commit 3023898b7d4a ("sock: fix sendmmsg for partial sendmsg")
	 * gives us the guarantee that at most one message, namely the last sent
	 * one, might have been sent partially. Check how many bytes of that
	 * message were sent, and re-send any missing bytes with a blocking
	 * sendmsg(), otherwise qemu will fail to parse any subsequent message.
	 */
	mh = &tcp_l2_mh_tap[ret - 1];
	if (mh->msg_len < mh->msg_hdr.msg_iov->iov_len) {
		uint8_t **iov_base = (uint8_t **)&mh->msg_hdr.msg_iov->iov_base;
		int part_sent = mh->msg_len;

		mh->msg_hdr.msg_iov->iov_len -= part_sent;
		*iov_base += part_sent;

		sendmsg(c->fd_tap, &mh->msg_hdr, MSG_NOSIGNAL);

		mh->msg_hdr.msg_iov->iov_len += part_sent;
		*iov_base -= part_sent;
	}

	conn->ts_ack_to_tap = *now;

	pcapmm(tcp_l2_mh_tap, ret);

	goto out;

err:
	if (errno != EAGAIN && errno != EWOULDBLOCK) {
		tcp_rst(c, conn);
		ret = -errno;
	}
	goto out;

zero_len:
	if (conn->state == ESTABLISHED_SOCK_FIN) {
		tcp_tap_epoll_mask(c, conn, EPOLLET);
		tcp_send_to_tap(c, conn, FIN | ACK, now);
		tcp_tap_state(conn, ESTABLISHED_SOCK_FIN_SENT);
	}

out:
	if (iov_rem)
		iov[fill_bufs - 1].iov_len = conn->mss_guest;
	if (send_bufs)
		iov_tap[send_bufs - 1].iov_len = mss_tap;

	return ret;
}

/**
 * tcp_data_from_tap() - tap data in ESTABLISHED{,SOCK_FIN}, CLOSE_WAIT states
 * @c:		Execution context
 * @conn:	Connection pointer
 * @msg:	Array of messages from tap
 * @count:	Count of messages
 * @now:	Current timestamp
 */
static void tcp_data_from_tap(struct ctx *c, struct tcp_tap_conn *conn,
			      struct tap_l4_msg *msg, int count,
			      struct timespec *now)
{
	int i, iov_i, ack = 0, fin = 0, psh = 0, retr = 0, keep = -1;
	struct msghdr mh = { .msg_iov = tcp_tap_iov };
	uint32_t max_ack_seq = conn->seq_ack_from_tap;
	uint16_t max_ack_seq_wnd = conn->wnd_from_tap;
	uint32_t seq_from_tap = conn->seq_from_tap;
	int partial_send = 0;
	uint16_t len;
	ssize_t n;

	for (i = 0, iov_i = 0; i < count; i++) {
		uint32_t seq, seq_offset, ack_seq;
		struct tcphdr *th;
		char *data;
		size_t off;

		th = (struct tcphdr *)(pkt_buf + msg[i].pkt_buf_offset);
		len = msg[i].l4_len;

		if (len < sizeof(*th)) {
			tcp_rst(c, conn);
			return;
		}

		off = th->doff * 4;
		if (off < sizeof(*th) || off > len) {
			tcp_rst(c, conn);
			return;
		}

		if (th->rst) {
			tcp_tap_destroy(c, conn);
			return;
		}

		len -= off;
		data = (char *)th + off;

		seq = ntohl(th->seq);
		ack_seq = ntohl(th->ack_seq);

		if (th->ack) {
			ack = 1;

			if (SEQ_GE(ack_seq, conn->seq_ack_from_tap) &&
			    SEQ_GE(ack_seq, max_ack_seq)) {
				/* Fast re-transmit */
				retr = !len && !th->fin &&
				       ack_seq == max_ack_seq &&
				       max_ack_seq_wnd == ntohs(th->window);

				max_ack_seq_wnd = ntohs(th->window);
				max_ack_seq = ack_seq;
			}
		}

		if (th->fin)
			fin = 1;

		if (th->psh)
			psh = 1;

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
		if (SEQ_GE(seq_offset, 0) && SEQ_LE(seq + len, seq_from_tap)) {
			/* Force sending ACK, sender might have lost one */
			psh = 1;
			continue;
		}

		if (SEQ_LT(seq_offset, 0)) {
			if (keep == -1)
				keep = i;
			continue;
		}

		tcp_tap_iov[iov_i].iov_base = data + seq_offset;
		tcp_tap_iov[iov_i].iov_len = len - seq_offset;
		seq_from_tap += tcp_tap_iov[iov_i].iov_len;
		iov_i++;

		if (keep == i)
			keep = -1;

		if (keep != -1)
			i = keep - 1;
	}

	tcp_clamp_window(conn, NULL, 0, max_ack_seq_wnd, 0);

	if (ack) {
		conn->ts_ack_from_tap = *now;
		conn->tap_data_noack = ((struct timespec) { 0, 0 });
		tcp_sock_consume(conn, max_ack_seq);
	}

	if (retr) {
		conn->seq_ack_from_tap = max_ack_seq;
		conn->seq_to_tap = max_ack_seq;
		tcp_data_from_sock(c, conn, now);
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
			tcp_send_to_tap(c, conn, FORCE_ACK, now);
		}

		if (errno == EINTR)
			goto eintr;

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			tcp_send_to_tap(c, conn, UPDATE_WINDOW, now);
			return;
		}
		tcp_rst(c, conn);
		return;
	}

	if (n < (seq_from_tap - conn->seq_from_tap)) {
		partial_send = 1;
		tcp_send_to_tap(c, conn, UPDATE_WINDOW, now);
	}

	conn->seq_from_tap += n;

out:
	if (keep != -1) {
		if (conn->seq_dup_ack != conn->seq_from_tap) {
			conn->seq_dup_ack = conn->seq_from_tap;
			tcp_send_to_tap(c, conn, DUP_ACK, now);
		}
		return;
	}

	if (ack) {
		if (conn->state == ESTABLISHED_SOCK_FIN_SENT &&
		    conn->seq_ack_from_tap == conn->seq_to_tap)
			tcp_tap_state(conn, CLOSE_WAIT);
	}

	if (fin && !partial_send) {
		conn->seq_from_tap++;

		if (conn->state == ESTABLISHED) {
			shutdown(conn->sock, SHUT_WR);
			tcp_tap_state(conn, FIN_WAIT_1);
			tcp_send_to_tap(c, conn, ACK, now);
		} else if (conn->state == CLOSE_WAIT) {
			shutdown(conn->sock, SHUT_WR);
			tcp_tap_state(conn, LAST_ACK);
			tcp_send_to_tap(c, conn, ACK, now);
		}
	} else {
		int ack_to_tap = timespec_diff_ms(now, &conn->ts_ack_to_tap);
		int ack_offset = conn->seq_from_tap - conn->seq_ack_to_tap;

		if (c->mode == MODE_PASTA ||
		    psh || SEQ_GE(ack_offset, conn->wnd_to_tap / 2) ||
		    ack_to_tap > ACK_INTERVAL) {
			tcp_send_to_tap(c, conn, psh ? FORCE_ACK : 0, now);
		}
	}
}

/**
 * tcp_tap_handler() - Handle packets from tap and state transitions
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Destination address
 * @msg:	Input messages
 * @count:	Message count
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 */
int tcp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_l4_msg *msg, int count, struct timespec *now)
{
	struct tcphdr *th = (struct tcphdr *)(pkt_buf + msg[0].pkt_buf_offset);
	uint16_t len = msg[0].l4_len;
	struct tcp_tap_conn *conn;

	conn = tcp_hash_lookup(c, af, addr, htons(th->source), htons(th->dest));
	if (!conn) {
		if (th->syn && !th->ack)
			tcp_conn_from_tap(c, af, addr, th, len, now);
		return 1;
	}

	if (th->rst) {
		tcp_tap_destroy(c, conn);
		return count;
	}

	conn->ts_tap_act = *now;

	switch (conn->state) {
	case SOCK_SYN_SENT:
		if (!th->syn || !th->ack) {
			tcp_rst(c, conn);
			return count;
		}

		tcp_clamp_window(conn, th, len, 0, 1);

		conn->mss_guest = tcp_opt_get(th, len, OPT_MSS, NULL, NULL);
		if (conn->mss_guest < 0)
			conn->mss_guest = MSS_DEFAULT;

		if (c->mode == MODE_PASST) {
			/* Don't upset qemu */
			conn->mss_guest = MIN(USHRT_MAX -
					      sizeof(uint32_t) -
					      sizeof(struct ethhdr) -
					      sizeof(struct ipv6hdr) -
					      sizeof(struct tcphdr),
					      conn->mss_guest);
		}

		/* info.tcpi_bytes_acked already includes one byte for SYN, but
		 * not for incoming connections.
		 */
		conn->seq_init_from_tap = ntohl(th->seq) + 1;
		conn->seq_from_tap = conn->seq_init_from_tap;
		conn->seq_ack_to_tap = conn->seq_from_tap;

		tcp_tap_state(conn, ESTABLISHED);

		/* The client might have sent data already, which we didn't
		 * dequeue waiting for SYN,ACK from tap -- check now.
		 */
		tcp_data_from_sock(c, conn, now);
		tcp_send_to_tap(c, conn, 0, now);

		tcp_tap_epoll_mask(c, conn, EPOLLIN | EPOLLRDHUP);
		break;
	case TAP_SYN_RCVD:
		if (th->fin) {
			conn->seq_from_tap++;

			shutdown(conn->sock, SHUT_WR);
			tcp_send_to_tap(c, conn, ACK, now);
			tcp_tap_state(conn, FIN_WAIT_1);
			break;
		}

		if (!th->ack) {
			tcp_rst(c, conn);
			return count;
		}

		tcp_clamp_window(conn, th, len, 0, 0);

		tcp_tap_state(conn, ESTABLISHED);
		if (count == 1)
			break;

		/* Falls through */
	case ESTABLISHED:
	case ESTABLISHED_SOCK_FIN:
	case ESTABLISHED_SOCK_FIN_SENT:
		tcp_tap_epoll_mask(c, conn, conn->events & ~EPOLLET);
		tcp_data_from_tap(c, conn, msg, count, now);
		return count;
	case CLOSE_WAIT:
	case FIN_WAIT_1_SOCK_FIN:
	case FIN_WAIT_1:
		if (th->ack) {
			conn->tap_data_noack = ((struct timespec) { 0, 0 });
			conn->ts_ack_from_tap = *now;
		}

		tcp_sock_consume(conn, ntohl(th->ack_seq));
		if (conn->state == FIN_WAIT_1_SOCK_FIN &&
		    conn->seq_ack_from_tap == conn->seq_to_tap) {
			tcp_tap_destroy(c, conn);
			return count;
		}

		tcp_tap_epoll_mask(c, conn, conn->events & ~EPOLLET);
		return count;
	case TAP_SYN_SENT:
	case LAST_ACK:
	case SPLICE_ACCEPTED:
	case SPLICE_CONNECT:
	case SPLICE_ESTABLISHED:
	case SPLICE_FIN_FROM:
	case SPLICE_FIN_TO:
	case SPLICE_FIN_BOTH:
	case CLOSED:	/* ;) */
		break;
	}

	return 1;
}

/**
 * tcp_connect_finish() - Handle completion of connect() from EPOLLOUT event
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @now:	Current timestamp
 */
static void tcp_connect_finish(struct ctx *c, struct tcp_tap_conn *conn,
			       struct timespec *now)
{
	socklen_t sl;
	int so;

	sl = sizeof(so);
	if (getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, &so, &sl) || so) {
		tcp_rst(c, conn);
		return;
	}

	if (tcp_send_to_tap(c, conn, SYN | ACK, now))
		return;

	/* Drop EPOLLOUT, only used to wait for connect() to complete */
	tcp_tap_epoll_mask(c, conn, EPOLLIN | EPOLLRDHUP);

	tcp_tap_state(conn, TAP_SYN_RCVD);
}

/**
 * tcp_splice_connect_finish() - Completion of connect() or call on success
 * @c:		Execution context
 * @conn:	Connection pointer
 * @v6:		Set on IPv6 connection
 */
static void tcp_splice_connect_finish(struct ctx *c,
				      struct tcp_splice_conn *conn, int v6)
{
	union epoll_ref ref_from = { .proto = IPPROTO_TCP, .s = conn->from,
				      .tcp = { .splice = 1, .v6 = v6,
					       .index = conn - ts } };
	union epoll_ref ref_to = { .proto = IPPROTO_TCP, .s = conn->to,
				   .tcp = { .splice = 1, .v6 = v6,
					    .index = conn - ts } };
	struct epoll_event ev_from, ev_to;
	int i;

	conn->pipe_from_to[0] = conn->pipe_to_from[0] = -1;
	conn->pipe_from_to[1] = conn->pipe_to_from[1] = -1;
	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
		if (splice_pipe_pool[i][0][0] > 0) {
			SWAP(conn->pipe_from_to[0], splice_pipe_pool[i][0][0]);
			SWAP(conn->pipe_from_to[1], splice_pipe_pool[i][0][1]);

			SWAP(conn->pipe_to_from[0], splice_pipe_pool[i][1][0]);
			SWAP(conn->pipe_to_from[1], splice_pipe_pool[i][1][1]);
			break;
		}
	}

	if (conn->pipe_from_to[0] <= 0) {
		if (pipe2(conn->pipe_to_from, O_NONBLOCK) ||
		    pipe2(conn->pipe_from_to, O_NONBLOCK)) {
			tcp_splice_destroy(c, conn);
			return;
		}

		fcntl(conn->pipe_from_to[0], F_SETPIPE_SZ, c->tcp.pipe_size);
		fcntl(conn->pipe_to_from[0], F_SETPIPE_SZ, c->tcp.pipe_size);
	}

	if (conn->state == SPLICE_CONNECT) {
		tcp_splice_state(conn, SPLICE_ESTABLISHED);

		ev_from.events = ev_to.events = EPOLLIN | EPOLLRDHUP;
		ev_from.data.u64 = ref_from.u64;
		ev_to.data.u64 = ref_to.u64;

		epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->from, &ev_from);
		epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->to, &ev_to);
	}
}

/**
 * tcp_splice_connect() - Create and connect socket for new spliced connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @v6:		Set on IPv6 connection
 * @port:	Destination port, host order
 *
 * Return: 0 for connect() succeeded or in progress, negative value on error
 */
static int tcp_splice_connect(struct ctx *c, struct tcp_splice_conn *conn,
			      int s, int v6, in_port_t port)
{
	int sock_conn = (s > 0) ? s : socket(v6 ? AF_INET6 : AF_INET,
					     SOCK_STREAM | SOCK_NONBLOCK,
					     IPPROTO_TCP);
	union epoll_ref ref_accept = { .proto = IPPROTO_TCP, .s = conn->from,
				       .tcp = { .splice = 1, .v6 = v6,
						.index = conn - ts } };
	union epoll_ref ref_conn = { .proto = IPPROTO_TCP, .s = sock_conn,
				     .tcp = { .splice = 1, .v6 = v6,
					      .index = conn - ts } };
	struct epoll_event ev_accept = { .data.u64 = ref_accept.u64 };
	struct epoll_event ev_conn = { .data.u64 = ref_conn.u64 };
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
	int ret, one = 1;
	socklen_t sl;

	conn->to = sock_conn;

	if (s <= 0)
		tcp_sock_set_bufsize(c, sock_conn);

	setsockopt(s, SOL_TCP, TCP_QUICKACK, &one, sizeof(one));

	if (v6) {
		sa = (struct sockaddr *)&addr6;
		sl = sizeof(addr6);
	} else {
		sa = (struct sockaddr *)&addr4;
		sl = sizeof(addr4);
	}

	if (connect(conn->to, sa, sl)) {
		if (errno != EINPROGRESS) {
			ret = -errno;
			close(sock_conn);
			return ret;
		}

		tcp_splice_state(conn, SPLICE_CONNECT);
		ev_conn.events = EPOLLOUT;
	} else {
		tcp_splice_state(conn, SPLICE_ESTABLISHED);
		tcp_splice_connect_finish(c, conn, v6);

		ev_accept.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
		ev_conn.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

		epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->from, &ev_accept);
	}

	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->to, &ev_conn);

	return 0;
}

/**
 * struct tcp_splice_connect_ns_arg - Arguments for tcp_splice_connect_ns()
 * @c:		Execution context
 * @conn:	Accepted inbound connection
 * @v6:		Set for inbound IPv6 connection
 * @port:	Destination port, host order
 * @ret:	Return value of tcp_splice_connect_ns()
 */
struct tcp_splice_connect_ns_arg {
	struct ctx *c;
	struct tcp_splice_conn *conn;
	int v6;
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
	ns_enter(a->c->pasta_pid);
	a->ret = tcp_splice_connect(a->c, a->conn, -1, a->v6, a->port);
	return 0;
}

/**
 * tcp_splice_new() - Handle new inbound, spliced connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @v6:		Set for IPv6 connection
 * @port:	Destination port, host order
 *
 * Return: return code from connect()
 */
static int tcp_splice_new(struct ctx *c, struct tcp_splice_conn *conn,
			  int v6, in_port_t port)
{
	struct tcp_splice_connect_ns_arg ns_arg = { c, conn, v6, port, 0 };
	int *sock_pool_p, i, s = -1;

	if (bitmap_isset(c->tcp.port_to_tap, port))
		sock_pool_p = v6 ? ns_sock_pool6 : ns_sock_pool4;
	else
		sock_pool_p = v6 ? init_sock_pool6 : init_sock_pool4;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++, sock_pool_p++) {
		if ((s = *sock_pool_p) > 0) {
			*sock_pool_p = -1;
			break;
		}
	}

	if (s <= 0 && bitmap_isset(c->tcp.port_to_tap, port)) {
		NS_CALL(tcp_splice_connect_ns, &ns_arg);
		return ns_arg.ret;
	}

	return tcp_splice_connect(c, conn, s, v6, port);
}

/**
 * tcp_conn_from_sock() - Handle new connection request from listening socket
 * @c:		Execution context
 * @ref:	epoll reference of listening socket
 * @now:	Current timestamp
 */
static void tcp_conn_from_sock(struct ctx *c, union epoll_ref ref,
			       struct timespec *now)
{
	union epoll_ref ref_conn = { .proto = IPPROTO_TCP,
				     .tcp.v6 = ref.tcp.v6 };
	struct sockaddr_storage sa;
	struct tcp_tap_conn *conn;
	struct epoll_event ev;
	socklen_t sl;
	int s;

	if (c->tcp.tap_conn_count >= MAX_TAP_CONNS)
		return;

	sl = sizeof(sa);
	s = accept4(ref.s, (struct sockaddr *)&sa, &sl, SOCK_NONBLOCK);
	if (s < 0)
		return;

	conn = &tt[c->tcp.tap_conn_count++];
	ref_conn.tcp.index = conn - tt;
	ref_conn.s = conn->sock = s;

	if (ref.tcp.v6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;

		if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr) ||
		    !memcmp(&sa6->sin6_addr, &c->addr6_seen, sizeof(c->gw6)) ||
		    !memcmp(&sa6->sin6_addr, &c->addr6, sizeof(c->gw6)))
			memcpy(&sa6->sin6_addr, &c->gw6, sizeof(c->gw6));

		memcpy(&conn->a.a6, &sa6->sin6_addr, sizeof(conn->a.a6));

		conn->sock_port = ntohs(sa6->sin6_port);
		conn->tap_port = ref.tcp.index;

		conn->seq_to_tap = tcp_seq_init(c, AF_INET6, &sa6->sin6_addr,
						conn->sock_port,
						conn->tap_port,
						now);
		conn->seq_init_to_tap = conn->seq_to_tap;

		tcp_hash_insert(c, conn, AF_INET6, &sa6->sin6_addr);
	} else {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;
		in_addr_t s_addr = ntohl(sa4->sin_addr.s_addr);

		memset(&conn->a.a4.zero,   0, sizeof(conn->a.a4.zero));
		memset(&conn->a.a4.one, 0xff, sizeof(conn->a.a4.one));

		if (s_addr >> IN_CLASSA_NSHIFT == IN_LOOPBACKNET ||
		    s_addr == INADDR_ANY || s_addr == htonl(c->addr4_seen))
			sa4->sin_addr.s_addr = c->gw4;

		memcpy(&conn->a.a4.a, &sa4->sin_addr, sizeof(conn->a.a4.a));

		conn->sock_port = ntohs(sa4->sin_port);
		conn->tap_port = ref.tcp.index;

		conn->seq_to_tap = tcp_seq_init(c, AF_INET, &sa4->sin_addr,
						conn->sock_port,
						conn->tap_port,
						now);
		conn->seq_init_to_tap = conn->seq_to_tap;

		tcp_hash_insert(c, conn, AF_INET, &sa4->sin_addr);
	}

	conn->seq_ack_from_tap = conn->seq_to_tap + 1;

	conn->wnd_from_tap = WINDOW_DEFAULT;

	conn->ts_sock_act = conn->ts_tap_act = *now;
	conn->ts_ack_from_tap = conn->ts_ack_to_tap = *now;

	tcp_send_to_tap(c, conn, SYN, now);

	conn->events = ev.events = EPOLLRDHUP;
	ev.data.u64 = ref_conn.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->sock, &ev);

	tcp_tap_state(conn, SOCK_SYN_SENT);

	tcp_get_sndbuf(conn);
}

/**
 * tcp_sock_handler_splice() - Handler for socket mapped to spliced connection
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 */
void tcp_sock_handler_splice(struct ctx *c, union epoll_ref ref,
			     uint32_t events)
{
	int move_from, move_to, *pipes, eof, never_read;
	uint8_t *rcvlowat_set, *rcvlowat_act;
	uint64_t *seq_read, *seq_write;
	struct tcp_splice_conn *conn;
	struct epoll_event ev;

	if (ref.tcp.listen) {
		int s, one = 1;

		if (c->tcp.splice_conn_count >= MAX_SPLICE_CONNS)
			return;

		if ((s = accept4(ref.s, NULL, NULL, SOCK_NONBLOCK)) < 0)
			return;

		setsockopt(s, SOL_TCP, TCP_QUICKACK, &one, sizeof(one));

		conn = &ts[c->tcp.splice_conn_count++];
		conn->from = s;
		tcp_splice_state(conn, SPLICE_ACCEPTED);

		if (tcp_splice_new(c, conn, ref.tcp.v6, ref.tcp.index))
			tcp_splice_destroy(c, conn);

		return;
	}

	conn = &ts[ref.tcp.index];

	if (events & EPOLLERR)
		goto close;

	if (conn->state == SPLICE_CONNECT && (events & EPOLLHUP))
		goto close;

	if (events & EPOLLOUT) {
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLRDHUP,
			.data.u64 = ref.u64,
		};

		if (conn->state == SPLICE_CONNECT)
			tcp_splice_connect_finish(c, conn, ref.tcp.v6);
		else if (conn->state == SPLICE_ESTABLISHED)
			epoll_ctl(c->epollfd, EPOLL_CTL_MOD, ref.s, &ev);

		move_to = ref.s;
		if (ref.s == conn->to) {
			move_from = conn->from;
			pipes = conn->pipe_from_to;
		} else {
			move_from = conn->to;
			pipes = conn->pipe_to_from;
		}
	} else {
		move_from = ref.s;
		if (ref.s == conn->from) {
			move_to = conn->to;
			pipes = conn->pipe_from_to;
		} else {
			move_to = conn->from;
			pipes = conn->pipe_to_from;
		}
	}

	if (events & EPOLLRDHUP) {
		if (ref.s == conn->from) {
			if (conn->state == SPLICE_ESTABLISHED)
				tcp_splice_state(conn, SPLICE_FIN_FROM);
			else if (conn->state == SPLICE_FIN_TO)
				tcp_splice_state(conn, SPLICE_FIN_BOTH);
		} else {
			if (conn->state == SPLICE_ESTABLISHED)
				tcp_splice_state(conn, SPLICE_FIN_TO);
			else if (conn->state == SPLICE_FIN_FROM)
				tcp_splice_state(conn, SPLICE_FIN_BOTH);
		}
	}

swap:
	eof = 0;
	never_read = 1;

	if (move_from == conn->from) {
		seq_read = &conn->from_read;
		seq_write = &conn->from_written;
		rcvlowat_set = splice_rcvlowat_set[0];
		rcvlowat_act = splice_rcvlowat_act[0];
	} else {
		seq_read = &conn->to_read;
		seq_write = &conn->to_written;
		rcvlowat_set = splice_rcvlowat_set[1];
		rcvlowat_act = splice_rcvlowat_act[1];
	}


	while (1) {
		int retry_write = 0, more = 0;
		ssize_t read, to_write = 0, written;

retry:
		read = splice(move_from, NULL, pipes[1], NULL, c->tcp.pipe_size,
			      SPLICE_F_MOVE);
		if (read < 0) {
			if (errno == EINTR)
				goto retry;

			if (errno != EAGAIN)
				goto close;

			to_write = c->tcp.pipe_size;
		} else if (!read) {
			eof = 1;
			to_write = c->tcp.pipe_size;
		} else {
			never_read = 0;
			to_write += read;
			if (read >= (long)c->tcp.pipe_size * 90 / 100)
				more = SPLICE_F_MORE;

			if (bitmap_isset(rcvlowat_set, conn - ts))
				bitmap_set(rcvlowat_act, conn - ts);
		}

eintr:
		written = splice(pipes[0], NULL, move_to, NULL, to_write,
				 SPLICE_F_MOVE | more);

		/* Most common case: skip updating counters. */
		if (read > 0 && read == written) {
			if (read >= (long)c->tcp.pipe_size * 10 / 100)
				continue;

			if (!bitmap_isset(rcvlowat_set, conn - ts) &&
			    read > (long)c->tcp.pipe_size / 10) {
				int lowat = c->tcp.pipe_size / 4;

				setsockopt(move_from, SOL_SOCKET, SO_RCVLOWAT,
					   &lowat, sizeof(lowat));

				bitmap_set(rcvlowat_set, conn - ts);
				bitmap_set(rcvlowat_act, conn - ts);
			}

			break;
		}

		*seq_read  += read > 0    ? read : 0;
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

			ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
			ref.s = move_to;
			ev.data.u64 = ref.u64,
			epoll_ctl(c->epollfd, EPOLL_CTL_MOD, move_to, &ev);
			break;
		} else if (never_read && written == (long)(c->tcp.pipe_size)) {
			goto retry;
		} else if (!never_read && written < to_write) {
			to_write -= written;
			goto retry;
		}

		if (eof)
			break;
	}

	if (*seq_read == *seq_write) {
		if (move_from == conn->from &&
		    (conn->state == SPLICE_FIN_FROM ||
		     conn->state == SPLICE_FIN_BOTH)) {
			if (!conn->from_fin_sent) {
				shutdown(conn->to, SHUT_WR);
				conn->from_fin_sent = 1;

				ev.events = 0;
				ref.s = move_from;
				ev.data.u64 = ref.u64,
				epoll_ctl(c->epollfd, EPOLL_CTL_MOD,
					  move_from, &ev);
			}

			if (conn->to_fin_sent)
				goto close;
		} else if (move_from == conn->to &&
		           (conn->state == SPLICE_FIN_TO ||
		            conn->state == SPLICE_FIN_BOTH)) {
			if (!conn->to_fin_sent) {
				shutdown(conn->from, SHUT_WR);
				conn->to_fin_sent = 1;

				ev.events = 0;
				ref.s = move_from;
				ev.data.u64 = ref.u64,
				epoll_ctl(c->epollfd, EPOLL_CTL_MOD,
					  move_from, &ev);
			}

			if (conn->from_fin_sent)
				goto close;
		}
	}

	if ((events & (EPOLLIN | EPOLLOUT)) == (EPOLLIN | EPOLLOUT)) {
		events = EPOLLIN;

		SWAP(move_from, move_to);
		if (pipes == conn->pipe_from_to)
			pipes = conn->pipe_to_from;
		else
			pipes = conn->pipe_from_to;

		goto swap;
	}

	return;

close:
	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->from, NULL);
	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->to, NULL);
	conn->state = CLOSED;
	return;
}

/**
 * tcp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
void tcp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      struct timespec *now)
{
	struct tcp_tap_conn *conn;

	if (ref.tcp.splice) {
		tcp_sock_handler_splice(c, ref, events);
		return;
	}

	if (ref.tcp.listen) {
		tcp_conn_from_sock(c, ref, now);
		return;
	}

	conn = &tt[ref.tcp.index];

	conn->ts_sock_act = *now;

	if (events & EPOLLERR) {
		if (conn->state != CLOSED)
			tcp_rst(c, conn);

		return;
	}

	switch (conn->state) {
	case TAP_SYN_SENT:
		if (events & EPOLLOUT)
			tcp_connect_finish(c, conn, now);
		else
			tcp_rst(c, conn);
		return;
	case ESTABLISHED_SOCK_FIN:
	case ESTABLISHED_SOCK_FIN_SENT:
	case ESTABLISHED:
		if (events & EPOLLRDHUP) {
			if (conn->state == ESTABLISHED)
				tcp_tap_state(conn, ESTABLISHED_SOCK_FIN);
		}
		tcp_data_from_sock(c, conn, now);
		return;
	case LAST_ACK:
		tcp_send_to_tap(c, conn, 0, now);
		if (conn->seq_ack_to_tap == conn->seq_from_tap + 1 ||
		    conn->seq_ack_to_tap == conn->seq_from_tap)
			tcp_tap_destroy(c, conn);
		return;
	case FIN_WAIT_1:
		if (events & EPOLLIN)
			tcp_data_from_sock(c, conn, now);
		if (events & EPOLLRDHUP) {
			tcp_send_to_tap(c, conn, FIN | ACK, now);
			tcp_tap_state(conn, FIN_WAIT_1_SOCK_FIN);
		}
		return;
	case CLOSE_WAIT:
	case FIN_WAIT_1_SOCK_FIN:
		if (events & EPOLLIN)
			tcp_data_from_sock(c, conn, now);
		if (events & EPOLLHUP) {
			if ((conn->seq_ack_to_tap == conn->seq_from_tap + 1 ||
			     conn->seq_ack_to_tap == conn->seq_from_tap) &&
			    (conn->seq_ack_from_tap == conn->seq_to_tap - 1 ||
			     conn->seq_ack_from_tap == conn->seq_to_tap)) {
				tcp_tap_destroy(c, conn);
			} else {
				tcp_send_to_tap(c, conn, ACK, now);
			}
		}
		return;
	case TAP_SYN_RCVD:
	case SOCK_SYN_SENT:
	case SPLICE_ACCEPTED:
	case SPLICE_CONNECT:
	case SPLICE_ESTABLISHED:
	case SPLICE_FIN_FROM:
	case SPLICE_FIN_TO:
	case SPLICE_FIN_BOTH:
	case CLOSED:
		break;
	}
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
		if (pipe(probe_pipe[i])) {
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
 * tcp_sock_init_one() - Initialise listening sockets for a given port
 * @c:		Execution context
 * @ns:		In pasta mode, if set, bind with loopback address in namespace
 * @port:	Port, host order
 */
static void tcp_sock_init_one(struct ctx *c, int ns, in_port_t port)
{
	union tcp_epoll_ref tref = { .listen = 1 };
	int s;

	if (ns)
		tref.index = (in_port_t)(port + tcp_port_delta_to_init[port]);
	else
		tref.index = (in_port_t)(port + tcp_port_delta_to_tap[port]);

	if (c->v4) {
		tref.v6 = 0;

		tref.splice = 0;
		if (!ns) {
			s = sock_l4(c, AF_INET, IPPROTO_TCP, port,
				    c->mode == MODE_PASTA ? BIND_EXT : BIND_ANY,
				    tref.u32);
			if (s > 0)
				tcp_sock_set_bufsize(c, s);
			else
				s = -1;

			if (c->tcp.init_detect_ports)
				tcp_sock_init_ext[port][V4] = s;
		}

		if (c->mode == MODE_PASTA) {
			tref.splice = 1;
			s = sock_l4(c, AF_INET, IPPROTO_TCP, port,
				    BIND_LOOPBACK, tref.u32);
			if (s > 0)
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

	if (c->v6) {
		tref.v6 = 1;

		tref.splice = 0;
		if (!ns) {
			s = sock_l4(c, AF_INET6, IPPROTO_TCP, port,
				    c->mode == MODE_PASTA ? BIND_EXT : BIND_ANY,
				    tref.u32);
			if (s > 0)
				tcp_sock_set_bufsize(c, s);
			else
				s = -1;

			if (c->tcp.init_detect_ports)
				tcp_sock_init_ext[port][V6] = s;
		}

		if (c->mode == MODE_PASTA) {
			tref.splice = 1;
			s = sock_l4(c, AF_INET6, IPPROTO_TCP, port,
				    BIND_LOOPBACK, tref.u32);
			if (s > 0)
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
 * Return: 0 on success, -1 on failure
 */
static int tcp_sock_init_ns(void *arg)
{
	struct ctx *c = (struct ctx *)arg;
	in_port_t port;

	ns_enter(c->pasta_pid);

	for (port = 0; port < USHRT_MAX; port++) {
		if (!bitmap_isset(c->tcp.port_to_init, port))
			continue;

		tcp_sock_init_one(c, 1, port);
	}

	return 0;
}

/**
 * tcp_splice_pipe_refill() - Refill pool of pre-opened pipes
 * @c:		Execution context
 */
static void tcp_splice_pipe_refill(struct ctx *c)
{
	int i;

	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
		if (splice_pipe_pool[i][0][0] > 0)
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
		if (ns_enter(a->c->pasta_pid))
			return 0;
		p4 = ns_sock_pool4;
		p6 = ns_sock_pool6;
	} else {
		p4 = init_sock_pool4;
		p6 = init_sock_pool6;
	}

	for (i = 0; a->c->v4 && i < TCP_SOCK_POOL_SIZE; i++, p4++) {
		if (*p4 > 0) {
			break;
		}
		*p4 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
		tcp_sock_set_bufsize(a->c, *p4);
	}

	for (i = 0; a->c->v6 && i < TCP_SOCK_POOL_SIZE; i++, p6++) {
		if (*p6 > 0) {
			break;
		}
		*p6 = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK,
			     IPPROTO_TCP);
		tcp_sock_set_bufsize(a->c, *p6);
	}

	return 0;
}

/**
 * tcp_sock_init() - Bind sockets for inbound connections, get key for sequence
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int tcp_sock_init(struct ctx *c, struct timespec *now)
{
	struct tcp_sock_refill_arg refill_arg = { c, 0 };
	in_port_t port;

	getrandom(&c->tcp.hash_secret, sizeof(c->tcp.hash_secret), GRND_RANDOM);

	tcp_probe_mem(c);

	for (port = 0; port < USHRT_MAX; port++) {
		if (!bitmap_isset(c->tcp.port_to_tap, port))
			continue;

		tcp_sock_init_one(c, 0, port);
	}

	if (c->v4)
		tcp_sock4_iov_init();

	if (c->v6)
		tcp_sock6_iov_init();

	c->tcp.refill_ts = *now;
	tcp_sock_refill(&refill_arg);

	if (c->mode == MODE_PASTA) {
		tcp_set_pipe_size(c);
		NS_CALL(tcp_sock_init_ns, c);

		refill_arg.ns = 1;
		NS_CALL(tcp_sock_refill, &refill_arg);
		tcp_splice_pipe_refill(c);

		c->tcp.port_detect_ts = *now;
	}

	return 0;
}

/**
 * tcp_timer_one() - Handler for timed events on one socket
 * @c:		Execution context
 * @conn:	Connection pointer
 * @ts:		Timestamp from caller
 */
static void tcp_timer_one(struct ctx *c, struct tcp_tap_conn *conn,
			  struct timespec *ts)
{
	int ack_from_tap = timespec_diff_ms(ts, &conn->ts_ack_from_tap);
	int ack_to_tap = timespec_diff_ms(ts, &conn->ts_ack_to_tap);
	int sock_act = timespec_diff_ms(ts, &conn->ts_sock_act);
	int tap_act = timespec_diff_ms(ts, &conn->ts_tap_act);
	int tap_data_noack;

	if (memcmp(&conn->tap_data_noack, &((struct timespec){ 0, 0 }),
		   sizeof(struct timespec)))
		tap_data_noack = 0;
	else
		tap_data_noack = timespec_diff_ms(ts, &conn->tap_data_noack);

	switch (conn->state) {
	case CLOSED:
		tcp_hash_remove(conn);
		tcp_table_tap_compact(c, conn);
		break;
	case SOCK_SYN_SENT:
	case TAP_SYN_RCVD:
		if (ack_from_tap > SYN_TIMEOUT)
			tcp_rst(c, conn);

		break;
	case ESTABLISHED_SOCK_FIN_SENT:
		if (tap_data_noack > FIN_TIMEOUT) {
			tcp_rst(c, conn);
			break;
		}
		/* Falls through */
	case ESTABLISHED:
	case ESTABLISHED_SOCK_FIN:
		if (tap_act > ACT_TIMEOUT && sock_act > ACT_TIMEOUT) {
			tcp_rst(c, conn);
			break;
		}

		if (!conn->wnd_to_tap)
			tcp_send_to_tap(c, conn, UPDATE_WINDOW, ts);
		else if (ack_to_tap > ACK_INTERVAL)
			tcp_send_to_tap(c, conn, 0, ts);

		if (tap_data_noack > ACK_TIMEOUT) {
			if (conn->seq_ack_from_tap < conn->seq_to_tap) {
				if (tap_data_noack > LAST_ACK_TIMEOUT) {
					tcp_rst(c, conn);
					break;
				}

				conn->seq_to_tap = conn->seq_ack_from_tap;
				tcp_data_from_sock(c, conn, ts);
			}
		}
		break;
	case CLOSE_WAIT:
	case FIN_WAIT_1_SOCK_FIN:
		if (tap_data_noack > FIN_TIMEOUT)
			tcp_rst(c, conn);
		break;
	case FIN_WAIT_1:
		if (sock_act > FIN_TIMEOUT)
			tcp_rst(c, conn);
		break;
	case LAST_ACK:
		if (sock_act > LAST_ACK_TIMEOUT)
			tcp_rst(c, conn);
		else if (tap_act > LAST_ACK_TIMEOUT)
			tcp_rst(c, conn);
		break;
	case TAP_SYN_SENT:
	case SPLICE_ACCEPTED:
	case SPLICE_CONNECT:
	case SPLICE_ESTABLISHED:
	case SPLICE_FIN_FROM:
	case SPLICE_FIN_TO:
	case SPLICE_FIN_BOTH:
		break;
	}
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
		ns_enter(a->c->pasta_pid);

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
	in_port_t port;

	if (a->bind_in_ns) {
		ns_enter(a->c->pasta_pid);

		for (port = 0; port < USHRT_MAX; port++) {
			if (!bitmap_isset(a->c->tcp.port_to_init, port)) {
				if (tcp_sock_ns[port][V4] > 0) {
					close(tcp_sock_ns[port][V4]);
					tcp_sock_ns[port][V4] = 0;
				}

				if (tcp_sock_ns[port][V6] > 0) {
					close(tcp_sock_ns[port][V6]);
					tcp_sock_ns[port][V6] = 0;
				}

				continue;
			}

			/* Don't loop back our own ports */
			if (bitmap_isset(a->c->tcp.port_to_tap, port))
				continue;

			if ((a->c->v4 && !tcp_sock_ns[port][V4]) ||
			    (a->c->v6 && !tcp_sock_ns[port][V6]))
				tcp_sock_init_one(a->c, 1, port);
		}
	} else {
		for (port = 0; port < USHRT_MAX; port++) {
			if (!bitmap_isset(a->c->tcp.port_to_tap, port)) {
				if (tcp_sock_init_ext[port][V4] > 0) {
					close(tcp_sock_init_ext[port][V4]);
					tcp_sock_init_ext[port][V4] = 0;
				}

				if (tcp_sock_init_ext[port][V6] > 0) {
					close(tcp_sock_init_ext[port][V6]);
					tcp_sock_init_ext[port][V6] = 0;
				}

				if (tcp_sock_init_lo[port][V4] > 0) {
					close(tcp_sock_init_lo[port][V4]);
					tcp_sock_init_lo[port][V4] = 0;
				}

				if (tcp_sock_init_lo[port][V6] > 0) {
					close(tcp_sock_init_lo[port][V6]);
					tcp_sock_init_lo[port][V6] = 0;
				}
				continue;
			}

			/* Don't loop back our own ports */
			if (bitmap_isset(a->c->tcp.port_to_init, port))
				continue;

			if ((a->c->v4 && !tcp_sock_init_ext[port][V4]) ||
			    (a->c->v6 && !tcp_sock_init_ext[port][V6]))
				tcp_sock_init_one(a->c, 0, port);
		}
	}

	return 0;
}

/**
 * tcp_timer() - Scan activity bitmap for sockets waiting for timed events
 * @c:		Execution context
 * @ts:		Timestamp from caller
 */
void tcp_timer(struct ctx *c, struct timespec *now)
{
	struct tcp_sock_refill_arg refill_arg = { c, 0 };
	int i;

	if (c->mode == MODE_PASTA) {
		if (timespec_diff_ms(now, &c->tcp.port_detect_ts) >
		    PORT_DETECT_INTERVAL) {
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

			c->tcp.port_detect_ts = *now;
		}
	}

	if (timespec_diff_ms(now, &c->tcp.refill_ts) > REFILL_INTERVAL) {
		tcp_sock_refill(&refill_arg);
		if (c->mode == MODE_PASTA) {
			refill_arg.ns = 1;
			if ((c->v4 && ns_sock_pool4[TCP_SOCK_POOL_TSH] <= 0) ||
			    (c->v6 && ns_sock_pool6[TCP_SOCK_POOL_TSH] <= 0))
				NS_CALL(tcp_sock_refill, &refill_arg);

			tcp_splice_pipe_refill(c);
		}
	}

	for (i = c->tcp.tap_conn_count - 1; i >= 0; i--)
		tcp_timer_one(c, tt + i, now);

	if (c->mode == MODE_PASTA) {
		for (i = c->tcp.splice_conn_count - 1; i >= 0; i--) {
			if ((ts + i)->state == CLOSED) {
				tcp_splice_destroy(c, ts + i);
				continue;
			}

			if (bitmap_isset(splice_rcvlowat_set[0], i) &&
			    !bitmap_isset(splice_rcvlowat_act[0], i)) {
				int lowat = 1;

				setsockopt((ts + i)->from, SOL_SOCKET,
					   SO_RCVLOWAT, &lowat, sizeof(lowat));
				bitmap_clear(splice_rcvlowat_set[0], i);
			}

			if (bitmap_isset(splice_rcvlowat_set[1], i) &&
			    !bitmap_isset(splice_rcvlowat_act[1], i)) {
				int lowat = 1;

				setsockopt((ts + i)->to, SOL_SOCKET,
					   SO_RCVLOWAT, &lowat, sizeof(lowat));
				bitmap_clear(splice_rcvlowat_set[1], i);
			}

			bitmap_clear(splice_rcvlowat_act[0], i);
			bitmap_clear(splice_rcvlowat_act[1], i);
		}
	}
}

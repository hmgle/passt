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
 *   - TODO: sequence collision attacks
 *
 * Portability is limited by usage of Linux-specific socket options.
 *
 *
 * Limits
 * ------
 *
 * To avoid the need for dynamic memory allocation, a maximum, reasonable amount
 * of connections is defined by MAX_TAP_CONNS below (currently 1M, close to
 * the maximum amount of file descriptors typically available to a process on
 * Linux).
 *
 * While fragmentation and reassembly are not implemented, tracking of missing
 * segments and retransmissions needs to be, thus data needs to linger on
 * sockets as long as it's not acknowledged by the guest, and read using
 * MSG_PEEK into a single, preallocated static buffer sized to the maximum
 * supported window, 16MiB. This imposes a practical limitation on window
 * scaling, that is, the maximum factor is 512. If a bigger window scaling
 * factor is observed during connection establishment, connection is reset and
 * reestablished by omitting the scaling factor in the SYN segment. This
 * limitation only applies to the window scaling advertised by the guest, but
 * if exceeded, no window scaling will be allowed at all toward either endpoint.
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
 *   - RST from tap		close socket > CLOSED
 *
 * - SOCK_SYN_SENT		new connected socket, SYN sent to tap
 *   - SYN,ACK from tap		ACK to tap > ESTABLISHED
 *   - socket error		RST to tap, close socket > CLOSED
 *   - SYN,ACK timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 *
 * - TAP_SYN_RCVD		connect() completed, SYN,ACK sent to tap
 *   - FIN from tap		write shutdown > FIN_WAIT_1
 *   - ACK from tap		> ESTABLISHED
 *   - socket error		RST to tap, close socket > CLOSED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 *
 * - ESTABLISHED		connection established, ready for data
 *   - FIN from tap		write shutdown > FIN_WAIT_1
 *   - zero-sized socket read	read shutdown, FIN to tap > ESTABLISHED_SOCK_FIN
 *   - socket error		RST to tap, close socket > CLOSED
 *   - data timeout		FIN to tap > ESTABLISHED_SOCK_FIN
 *   - RST from tap		close socket > CLOSED
 *
 * - ESTABLISHED_SOCK_FIN	socket closing connection, FIN sent to tap
 *   - ACK from tap		> CLOSE_WAIT
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 *
 * - CLOSE_WAIT			socket closing connection, ACK from tap
 *   - FIN from tap		write shutdown > LAST_ACK
 *   - socket error		RST to tap, close socket > CLOSED
 *   - FIN timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 * 
 * - LAST_ACK			socket started close, tap completed it
 *   - anything from socket	close socket > CLOSED
 *   - socket error		RST to tap, close socket > CLOSED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 *
 * - FIN_WAIT_1			tap closing connection, FIN sent to socket
 *   - zero-sized socket read	FIN,ACK to tap, shutdown > FIN_WAIT_1_SOCK_FIN
 *   - socket error		RST to tap, close socket > CLOSED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 *
 * - FIN_WAIT_1_SOCK_FIN	tap closing connection, FIN received from socket
 *   - ACK from tap		close socket > CLOSED
 *   - socket error		RST to tap, close socket > CLOSED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
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
 * @tap_window:		last window size received from tap, scaled
 * @tcpi_acked_last:	most recent value of tcpi_bytes_acked (TCP_INFO)
 * 
 * - from socket to tap:
 *   - on new data from socket:
 *     - peek into buffer
 *     - send data to tap:
 *       - starting at offset (@seq_to_tap - @seq_ack_from_tap)
 *       - in MSS-sized segments
 *       - increasing @seq_to_tap at each segment
 *       - up to window (until @seq_to_tap - @seq_ack_from_tap <= @tap_window)
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
 *       @ts_sock elapsed, reset @seq_to_tap to @seq_ack_from_tap, and
 *       resend data with the steps listed above
 *
 * - from tap to socket:
 *   - on packet from tap:
 *     - set @ts_tap
 *     - set TCP_WINDOW_CLAMP from TCP header from tap
 *     - check seq from header against @seq_from_tap, if data is missing, send
 *       two ACKs with number @seq_ack_to_tap, discard packet
 *     - otherwise queue data to socket, set @seq_from_tap to seq from header
 *       plus payload length
 *     - query socket for TCP_INFO, on tcpi_bytes_acked > @tcpi_acked_last,
 *       set @tcpi_acked_last to tcpi_bytes_acked, set @seq_ack_to_tap
 *       to (tcpi_bytes_acked + @seq_init_from_tap) % 2^32 and
 *       send ACK to tap
 *   - periodically:
 *     - query socket for TCP_INFO, on tcpi_bytes_acked > @tcpi_acked_last, 
 *       set @tcpi_acked_last to tcpi_bytes_acked, set @seq_ack_to_tap
 *       to (tcpi_bytes_acked + @seq_init_from_tap) % 2^32 and
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
 * just four states:
 *
 * - CLOSED:			no connection
 * - SPLICE_ACCEPTED:		accept() on the listening socket succeeded
 * - SPLICE_CONNECT:		connect() issued in the destination namespace
 * - SPLICE_ESTABLISHED:	connect() succeeded, packets are transferred
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
#include <unistd.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <time.h>

#include "util.h"
#include "passt.h"
#include "tap.h"
#include "siphash.h"

#define MAX_TAP_CONNS			(128 * 1024)
#define MAX_SPLICE_CONNS		(128 * 1024)

#define PIPE_SIZE			(1024 * 1024)

#define TCP_HASH_TABLE_LOAD		70		/* % */
#define TCP_HASH_TABLE_SIZE		(MAX_TAP_CONNS * 100 /		\
					 TCP_HASH_TABLE_LOAD)

#define MAX_WS				9
#define MAX_WINDOW			(1 << (16 + (MAX_WS)))
#define MSS_DEFAULT			536
#define WINDOW_DEFAULT			14600		/* RFC 6928 */

#define SYN_TIMEOUT			240000		/* ms */
#define ACK_TIMEOUT			2000
#define ACK_INTERVAL			50
#define ACT_TIMEOUT			7200000
#define FIN_TIMEOUT			240000
#define LAST_ACK_TIMEOUT		240000


/* We need to include <linux/tcp.h> for tcpi_bytes_acked, instead of
 * <netinet/tcp.h>, but that doesn't include a definition for SOL_TCP
 */
#define SOL_TCP				IPPROTO_TCP

enum tcp_state {
	CLOSED = 0,
	TAP_SYN_SENT,
	SOCK_SYN_SENT,
	TAP_SYN_RCVD,
	ESTABLISHED,
	ESTABLISHED_SOCK_FIN,
	CLOSE_WAIT,
	LAST_ACK,
	FIN_WAIT_1,
	FIN_WAIT_1_SOCK_FIN,
	SPLICE_ACCEPTED,
	SPLICE_CONNECT,
	SPLICE_ESTABLISHED,
};
#define TCP_STATE_STR_SIZE	(SPLICE_ESTABLISHED + 1)

static char *tcp_state_str[TCP_STATE_STR_SIZE] __attribute((__unused__)) = {
	"CLOSED", "TAP_SYN_SENT", "SOCK_SYN_SENT", "TAP_SYN_RCVD",
	"ESTABLISHED", "ESTABLISHED_SOCK_FIN", "CLOSE_WAIT", "LAST_ACK",
	"FIN_WAIT_1", "FIN_WAIT_1_SOCK_FIN",
	"SPLICE_ACCEPTED", "SPLICE_CONNECT", "SPLICE_ESTABLISHED",
};

#define FIN		(1 << 0)
#define SYN		(1 << 1)
#define RST		(1 << 2)
#define ACK		(1 << 4)
/* Flags for internal usage */
#define ZERO_WINDOW	(1 << 5)

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
 * @state:		TCP connection state
 * @seq_to_tap:		Next sequence for packets to tap
 * @seq_ack_from_tap:	Last ACK number received from tap
 * @seq_from_tap:	Next sequence for packets from tap (not actually sent)
 * @seq_ack_to_tap:	Last ACK number sent to tap
 * @seq_init_from_tap:	Initial sequence number from tap
 * @tcpi_acked_last:	Most recent value of tcpi_bytes_acked (TCP_INFO query)
 * @ws_allowed:		Window scaling allowed
 * @ws:			Window scaling factor
 * @tap_window:		Last window size received from tap, scaled
 * @window_clamped:	Window was clamped on socket at least once
 * @no_snd_wnd:		Kernel won't report window (without commit 8f7baad7f035)
 * @tcpi_acked_last:	Most recent value of tcpi_snd_wnd (TCP_INFO query)
 * @ts_sock:		Last activity timestamp from socket for timeout purposes
 * @ts_tap:		Last activity timestamp from tap for timeout purposes
 * @ts_ack_tap:		Last ACK segment timestamp from tap for timeout purposes
 * @mss_guest:		Maximum segment size advertised by guest
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
	enum tcp_state state;

	uint32_t seq_to_tap;
	uint32_t seq_ack_from_tap;
	uint32_t seq_from_tap;
	uint32_t seq_ack_to_tap;
	uint32_t seq_init_from_tap;
	uint64_t tcpi_acked_last;

	int ws_allowed;
	int ws;
	uint32_t tap_window;
	int window_clamped;
	int no_snd_wnd;
	uint32_t tcpi_snd_wnd;

	struct timespec ts_sock;
	struct timespec ts_tap;
	struct timespec ts_ack_tap;

	int mss_guest;
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
	int v6;
};

/* Socket receive buffer */
static char sock_buf[MAX_WINDOW];

/* Bitmap, activity monitoring needed for connection via tap */
static uint8_t tcp_act[MAX_TAP_CONNS / 8] = { 0 };

/* TCP connections */
static struct tcp_tap_conn tt[MAX_TAP_CONNS];
static struct tcp_splice_conn ts[MAX_SPLICE_CONNS];

/* Table for lookup from remote address, local port, remote port */
static struct tcp_tap_conn *tt_hash[TCP_HASH_TABLE_SIZE];

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
 * tcp_table_tap_compact - Compaction tap connection table
 * @c:		Execution context
 * @hole:	Pointer to recently closed connection
 */
static void tcp_table_tap_compact(struct ctx *c, struct tcp_tap_conn *hole)
{
	union epoll_ref ref = { .proto = IPPROTO_TCP, .tcp.index = hole - tt };
	struct tcp_tap_conn *from, *to;
	struct epoll_event ev;

	if ((hole - tt) == --c->tcp.tap_conn_count) {
		bitmap_clear(tcp_act, hole - tt);
		debug("TCP: hash table compaction: index %i (%p) was max index",
		      hole - tt, hole);
		return;
	}

	from = &tt[c->tcp.tap_conn_count];
	memcpy(hole, from, sizeof(*hole));
	from->state = CLOSED;

	to = hole;
	tcp_hash_update(from, to);

	if (to->state == SOCK_SYN_SENT)
		ev.events = EPOLLRDHUP;
	else if (to->state == TAP_SYN_SENT)
		ev.events = EPOLLOUT | EPOLLRDHUP;
	else
		ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;

	ref.tcp.v6 = !IN6_IS_ADDR_V4MAPPED(&to->a.a6);
	ref.s = from->sock;
	ev.data.u64 = ref.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, from->sock, &ev);

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
	tcp_hash_remove(conn);
	tcp_table_tap_compact(c, conn);
}

static void tcp_rst(struct ctx *c, struct tcp_tap_conn *conn);

/**
 * tcp_send_to_tap() - Send segment to tap, with options and values from socket
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags to set
 * @in:		Payload buffer
 * @len:	Payload length
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
static int tcp_send_to_tap(struct ctx *c, struct tcp_tap_conn *conn,
			   int flags, char *in, int len)
{
	char buf[USHRT_MAX] = { 0 }, *data;
	struct tcp_info info = { 0 };
	socklen_t sl = sizeof(info);
	struct tcphdr *th;
	int ws = 0, err;

	if (conn->seq_from_tap == conn->seq_ack_to_tap && !flags && len) {
		err = 0;
		info.tcpi_bytes_acked = conn->tcpi_acked_last;
		info.tcpi_snd_wnd = conn->tcpi_snd_wnd;
	} else {
		err = getsockopt(conn->sock, SOL_TCP, TCP_INFO, &info, &sl);
		if (err && !(flags & RST)) {
			tcp_rst(c, conn);
			return err;
		}

		conn->tcpi_snd_wnd = info.tcpi_snd_wnd;
	}

	th = (struct tcphdr *)buf;
	data = (char *)(th + 1);
	th->doff = sizeof(*th) / 4;

	if ((flags & SYN) && !err) {
		/* Options: MSS, NOP and window scale if allowed (4-8 bytes) */
		*data++ = OPT_MSS;
		*data++ = OPT_MSS_LEN;
		*(uint16_t *)data = htons(info.tcpi_snd_mss);
		data += OPT_MSS_LEN - 2;
		th->doff += OPT_MSS_LEN / 4;

		/* Check if kernel includes commit:
		 *	8f7baad7f035 ("tcp: Add snd_wnd to TCP_INFO")
		 */
		conn->no_snd_wnd = !info.tcpi_snd_wnd;

		if (conn->ws_allowed && (ws = info.tcpi_snd_wscale) &&
		    !conn->no_snd_wnd) {
			*data++ = OPT_NOP;

			*data++ = OPT_WS;
			*data++ = OPT_WS_LEN;
			*data++ = ws;

			th->doff += (1 + OPT_WS_LEN) / 4;
		}

		/* RFC 793, 3.1: "[...] and the first data octet is ISN+1." */
		th->seq = htonl(conn->seq_to_tap++);
	} else {
		th->seq = htonl(conn->seq_to_tap);
		conn->seq_to_tap += len;
	}

	if (!err && ((info.tcpi_bytes_acked > conn->tcpi_acked_last) ||
		     (flags & ACK) || len)) {
		th->ack = 1;

		conn->seq_ack_to_tap = info.tcpi_bytes_acked +
				       conn->seq_init_from_tap;

		if (conn->state == LAST_ACK) {
			conn->seq_ack_to_tap = conn->seq_from_tap + 1;
			th->seq = htonl(ntohl(th->seq) + 1);
		}

		th->ack_seq = htonl(conn->seq_ack_to_tap);

		conn->tcpi_acked_last = info.tcpi_bytes_acked;
	} else {
		if (!len && !flags)
			return 0;

		th->ack = th->ack_seq = 0;
	}

	th->rst = !!(flags & RST);
	th->syn = !!(flags & SYN);
	th->fin = !!(flags & FIN);

	th->source = htons(conn->sock_port);
	th->dest = htons(conn->tap_port);

	if (flags & ZERO_WINDOW) {
		th->window = 0;
	} else if (!err && !conn->no_snd_wnd) {
		/* First value sent by receiver is not scaled */
		th->window = htons(info.tcpi_snd_wnd >>
				   (th->syn ? 0 : info.tcpi_snd_wscale));
	} else {
		th->window = htons(WINDOW_DEFAULT);
	}

	th->urg_ptr = 0;
	th->check = 0;

	memcpy(data, in, len);

	tap_ip_send(c, &conn->a.a6, IPPROTO_TCP, buf, th->doff * 4 + len);

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

	tcp_send_to_tap(c, conn, RST, NULL, 0);
	tcp_tap_destroy(c, conn);
}

/**
 * tcp_clamp_window() - Set window and scaling from option, clamp on socket
 * @conn:	Connection pointer
 * @th:		TCP header, from tap
 * @len:	Buffer length, at L4
 * @init:	Set if this is the very first segment from tap
 */
static void tcp_clamp_window(struct tcp_tap_conn *conn, struct tcphdr *th,
			     int len, int init)
{
	if (init) {
		conn->ws = tcp_opt_get(th, len, OPT_WS, NULL, NULL);
		conn->ws_allowed = conn->ws >= 0 && conn->ws <= MAX_WS;
		conn->ws *= conn->ws_allowed;

		/* RFC 7323, 2.2: first value is not scaled. Also, don't clamp
		 * yet, to avoid getting a zero scale just because we set a
		 * small window now.
		 */
		conn->tap_window = ntohs(th->window);
		conn->window_clamped = 0;
	} else {
		unsigned int window = ntohs(th->window) << conn->ws;

		if (conn->tap_window == window && conn->window_clamped)
			return;

		conn->tap_window = window;
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
	struct epoll_event ev = { .events = EPOLLIN | EPOLLET | EPOLLRDHUP };
	union epoll_ref ref = { .proto = IPPROTO_TCP };
	const struct sockaddr *sa;
	struct tcp_tap_conn *conn;
	socklen_t sl;
	int s;

	if (c->tcp.tap_conn_count >= MAX_TAP_CONNS)
		return;

	ref.s = s = socket(af, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (s < 0)
		return;

	conn = &tt[c->tcp.tap_conn_count++];
	conn->sock = s;

	conn->mss_guest = tcp_opt_get(th, len, OPT_MSS, NULL, NULL);
	if (conn->mss_guest < 0)
		conn->mss_guest = MSS_DEFAULT;
	sl = sizeof(conn->mss_guest);
	setsockopt(s, SOL_TCP, TCP_MAXSEG, &conn->mss_guest, sl);

	tcp_clamp_window(conn, th, len, 1);

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

	conn->ts_sock = conn->ts_tap = conn->ts_ack_tap = *now;

	bitmap_set(tcp_act, conn - tt);

	conn->seq_init_from_tap = ntohl(th->seq);
	conn->seq_from_tap = conn->seq_init_from_tap + 1;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	conn->seq_to_tap = tcp_seq_init(c, af, addr, th->dest, th->source, now);
	conn->seq_ack_from_tap = conn->seq_to_tap + 1;

	tcp_hash_insert(c, conn, af, addr);

	if (connect(s, sa, sl)) {
		tcp_tap_state(conn, TAP_SYN_SENT);

		if (errno != EINPROGRESS) {
			tcp_rst(c, conn);
			return;
		}

		ev.events = EPOLLOUT | EPOLLRDHUP;
	} else {
		tcp_tap_state(conn, TAP_SYN_RCVD);

		if (tcp_send_to_tap(c, conn, SYN | ACK, NULL, 0))
			return;
	}

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
	union epoll_ref ref_from = { .proto = IPPROTO_TCP,
				     .tcp.index = hole - ts };
	union epoll_ref ref_to = { .proto = IPPROTO_TCP,
				   .tcp.index = hole - ts };
	struct tcp_splice_conn *move;
	struct epoll_event ev_from;
	struct epoll_event ev_to;

	if ((hole - ts) == --c->tcp.splice_conn_count)
		return;

	move = &ts[c->tcp.splice_conn_count];
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
		ev_from.events = EPOLLET | EPOLLRDHUP;
		ev_to.events = EPOLLET | EPOLLOUT | EPOLLRDHUP;
	} else {
		ev_from.events = EPOLLET | EPOLLIN | EPOLLOUT | EPOLLRDHUP;
		ev_to.events = EPOLLET | EPOLLIN | EPOLLOUT | EPOLLRDHUP;
	}

	ev_from.data.u64 = ref_from.u64;
	ev_to.data.u64 = ref_to.u64;

	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, move->from, &ev_from);
	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, move->to, &ev_to);
}

/**
 * tcp_tap_destroy() - Close spliced connection and pipes, drop from epoll
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_splice_destroy(struct ctx *c, struct tcp_splice_conn *conn)
{
	switch (conn->state) {
	case SPLICE_ESTABLISHED:
		if (conn->pipe_from_to[0] != -1) {
			close(conn->pipe_from_to[0]);
			close(conn->pipe_from_to[1]);
		}
		if (conn->pipe_to_from[0] != -1) {
			close(conn->pipe_to_from[0]);
			close(conn->pipe_to_from[1]);
		}
		/* Falls through */
	case SPLICE_CONNECT:
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->from, NULL);
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->to, NULL);
		close(conn->to);
		/* Falls through */
	case SPLICE_ACCEPTED:
		close(conn->from);
		tcp_splice_state(conn, CLOSED);
		tcp_table_splice_compact(c, conn);
		return;
	default:
		return;
	}
}

/**
 * tcp_send_to_sock() - Send buffer to socket, update timestamp and sequence
 * @c:			Execution context
 * @conn:		Connection pointer
 * @data:		Data buffer
 * @len:		Length at L4
 * @extra_flags:	Additional flags for send(), if any
 *
 * Return: negative on socket error with connection reset, 0 otherwise
 */
static int tcp_send_to_sock(struct ctx *c, struct tcp_tap_conn *conn,
			    char *data, int len, int extra_flags)
{
	int err = send(conn->sock, data, len,
		       MSG_DONTWAIT | MSG_NOSIGNAL | extra_flags);

	if (err < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			tcp_send_to_tap(c, conn, ZERO_WINDOW, NULL, 0);
			return err;
		}

		err = errno;
		tcp_rst(c, conn);
		return -err;
	}

	conn->seq_from_tap += err;

	return 0;
}

/**
 * tcp_sock_consume() - Consume (discard) data from buffer, update ACK sequence
 * @conn:	Connection pointer
 * @ack_seq:	ACK sequence, host order
 */
static void tcp_sock_consume(struct tcp_tap_conn *conn, uint32_t ack_seq)
{
	uint32_t to_ack;

	/* Implicitly take care of wrap-arounds */
	to_ack = ack_seq - conn->seq_ack_from_tap;

	/* Simply ignore out-of-order ACKs: we already consumed the data we
	 * needed from the buffer, and we won't rewind back to a lower ACK
	 * sequence.
	 */
	if (to_ack > MAX_WINDOW)
		return;

	if (to_ack)
		recv(conn->sock, NULL, to_ack, MSG_DONTWAIT | MSG_TRUNC);

	conn->seq_ack_from_tap = ack_seq;
}

/**
 * tcp_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @conn:	Connection pointer
 * @now:	Current timestamp
 *
 * Return: negative on connection reset, 1 on pending data, 0 otherwise
 */
static int tcp_data_from_sock(struct ctx *c, struct tcp_tap_conn *conn,
			      struct timespec *now)
{
	uint32_t offset = conn->seq_to_tap - conn->seq_ack_from_tap;
	int len, err, left, send, s = conn->sock;

	if (!conn->tap_window || offset >= conn->tap_window)
		return 1;

	len = recv(s, sock_buf,
		   /* TODO: Drop 64KiB limit (needed for responsiveness) once
		    * tap-side coalescing and zero-copy are fully implemented.
		    */
		   MIN(64 * 1024, conn->tap_window),
		   /* Don't dequeue until acknowledged by guest */
		   MSG_DONTWAIT | MSG_PEEK);

	if (len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			tcp_rst(c, conn);
			return -errno;
		}
		return 0;
	}

	if (len == 0) {
		if (conn->state >= ESTABLISHED_SOCK_FIN)
			return 0;

		tcp_tap_state(conn, ESTABLISHED_SOCK_FIN);
		if ((err = tcp_send_to_tap(c, conn, FIN | ACK, NULL, 0)))
			return err;

		left = 0;
		goto out;
	}

	left = len - offset;
	while (left && (offset + conn->mss_guest <= conn->tap_window)) {
		if (left < conn->mss_guest)
			send = left;
		else
			send = conn->mss_guest;

		if (offset + send > MAX_WINDOW) {
			tcp_rst(c, conn);
			return -EIO;
		}

		err = tcp_send_to_tap(c, conn, 0, sock_buf + offset, send);
		if (err)
			return err;

		offset += send;
		left -= send;
	}

out:
	conn->ts_sock = *now;

	return !!left;
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
		    struct tap_msg *msg, int count, struct timespec *now)
{
	union epoll_ref ref = { .proto = IPPROTO_TCP,
				.tcp.v6 = ( af == AF_INET6 ) };

	/* TODO: Implement message batching for TCP */
	struct tcphdr *th = (struct tcphdr *)msg[0].l4h;
	size_t len = msg[0].l4_len;

	struct tcp_tap_conn *conn;
	struct epoll_event ev;
	size_t off, skip = 0;
	int ws, i;

	uint32_t __seq_max;

	if (len < sizeof(*th))
		return 1;

	off = th->doff * 4;
	if (off < sizeof(*th) || off > len)
		return 1;

	conn = tcp_hash_lookup(c, af, addr, htons(th->source), htons(th->dest));
	if (!conn) {
		if (th->syn)
			tcp_conn_from_tap(c, af, addr, th, len, now);
		return 1;
	}

	/* TODO: Partial ACK coalescing, merge with message coalescing */
	for (i = 0; conn->state == ESTABLISHED && i < count; i++) {
		struct tcphdr *__th = (struct tcphdr *)msg[i].l4h;
		size_t __len = msg[i].l4_len;
		uint32_t __this;

		if (__len < sizeof(*th))
			break;

		off = __th->doff * 4;
		if (off < sizeof(*th) || off > __len)
			break;

		if (!i && (!th->ack || len != off))
			break;

		__this = ntohl(th->ack_seq);

		if (!i || __this - __seq_max < MAX_WINDOW)
			__seq_max = __this;

		if ((!th->ack || len != off) && i) {
			tcp_sock_consume(conn, __seq_max);
			conn->ts_tap = *now;
			return i;
		}
	}

	if (th->rst) {
		tcp_tap_destroy(c, conn);
		return 1;
	}

	tcp_clamp_window(conn, th, len, th->syn && th->ack);

	conn->ts_tap = *now;

	if (ntohl(th->seq) < conn->seq_from_tap &&
	    conn->seq_from_tap - ntohl(th->seq) < MAX_WINDOW) {
		skip = conn->seq_from_tap - ntohl(th->seq);
	}

	switch (conn->state) {
	case SOCK_SYN_SENT:
		if (!th->syn || !th->ack) {
			tcp_rst(c, conn);
			return 1;
		}

		conn->mss_guest = tcp_opt_get(th, len, OPT_MSS, NULL, NULL);
		if (conn->mss_guest < 0)
			conn->mss_guest = MSS_DEFAULT;

		ws = tcp_opt_get(th, len, OPT_WS, NULL, NULL);
		if (ws > MAX_WS) {
			if (tcp_send_to_tap(c, conn, RST, NULL, 0))
				return 1;

			conn->seq_to_tap = 0;
			conn->ws_allowed = 0;
			tcp_send_to_tap(c, conn, SYN, NULL, 0);
			return 1;
		}

		/* info.tcpi_bytes_acked already includes one byte for SYN, but
		 * not for incoming connections.
		 */
		conn->seq_init_from_tap = ntohl(th->seq) + 1;
		conn->seq_from_tap = conn->seq_init_from_tap;
		conn->seq_ack_to_tap = conn->seq_from_tap;

		tcp_tap_state(conn, ESTABLISHED);
		tcp_send_to_tap(c, conn, ACK, NULL, 0);

		/* The client might have sent data already, which we didn't
		 * dequeue waiting for SYN,ACK from tap -- check now.
		 */
		tcp_data_from_sock(c, conn, now);

		ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
		ref.s = conn->sock;
		ref.tcp.index = conn - tt;
		ev.data.u64 = ref.u64;
		epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->sock, &ev);
		break;
	case TAP_SYN_RCVD:
		if (th->fin) {
			shutdown(conn->sock, SHUT_WR);
			tcp_tap_state(conn, FIN_WAIT_1);
			break;
		}

		if (!th->ack) {
			tcp_rst(c, conn);
			return 1;
		}

		tcp_tap_state(conn, ESTABLISHED);
		break;
	case ESTABLISHED:
	case ESTABLISHED_SOCK_FIN:
		conn->ts_ack_tap = *now;

		if (ntohl(th->ack_seq) > conn->seq_to_tap &&
		    (conn->seq_to_tap - ntohl(th->ack_seq)) > MAX_WINDOW) {
			return count;
		}

		if (th->ack) {
			tcp_sock_consume(conn, ntohl(th->ack_seq));

			if (conn->state == ESTABLISHED_SOCK_FIN) {
				if (!tcp_data_from_sock(c, conn, now))
					tcp_tap_state(conn, CLOSE_WAIT);
			} else {
				tcp_data_from_sock(c, conn, now);
			}
		}

		if (ntohl(th->seq) > conn->seq_from_tap) {
			tcp_send_to_tap(c, conn, ACK, NULL, 0);
			tcp_send_to_tap(c, conn, ACK, NULL, 0);
			return count;
		}

		if (skip < len - off &&
		    tcp_send_to_sock(c, conn,
				     msg[0].l4h + off + skip, len - off - skip,
				     (count > 1) ? MSG_MORE : 0))
			return 1;

		if (count == 1)
			tcp_send_to_tap(c, conn, ACK, NULL, 0);

		if (th->fin) {
			shutdown(conn->sock, SHUT_WR);
			if (conn->state == ESTABLISHED)
				tcp_tap_state(conn, FIN_WAIT_1);
			else
				tcp_tap_state(conn, LAST_ACK);
		}

		break;
	case CLOSE_WAIT:
		tcp_sock_consume(conn, ntohl(th->ack_seq));

		if (skip < (len - off) &&
		    tcp_send_to_sock(c, conn,
				     msg[0].l4h + off + skip, len - off - skip,
				     th->psh ? 0 : MSG_MORE))
			break;

		if (th->fin) {
			shutdown(conn->sock, SHUT_WR);
			tcp_tap_state(conn, LAST_ACK);
		}

		break;
	case FIN_WAIT_1_SOCK_FIN:
		if (th->ack)
			tcp_tap_destroy(c, conn);
		break;
	case FIN_WAIT_1:
	case TAP_SYN_SENT:
	case LAST_ACK:
	case SPLICE_ACCEPTED:
	case SPLICE_CONNECT:
	case SPLICE_ESTABLISHED:
	case CLOSED:	/* ;) */
		break;
	}

	return 1;
}

/**
 * tcp_connect_finish() - Handle completion of connect() from EPOLLOUT event
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @ref:	epoll reference
 */
static void tcp_connect_finish(struct ctx *c, struct tcp_tap_conn *conn,
			       union epoll_ref ref)
{
	struct epoll_event ev;
	socklen_t sl;
	int so;

	sl = sizeof(so);
	if (getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, &so, &sl) || so) {
		tcp_rst(c, conn);
		return;
	}

	if (tcp_send_to_tap(c, conn, SYN | ACK, NULL, 0))
		return;

	/* Drop EPOLLOUT, only used to wait for connect() to complete */
	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
	ev.data.u64 = ref.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->sock, &ev);

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

	if (conn->state == SPLICE_CONNECT) {
		socklen_t sl;
		int so;

		sl = sizeof(so);
		if (getsockopt(conn->to, SOL_SOCKET, SO_ERROR, &so, &sl) ||
		    so) {
			tcp_splice_destroy(c, conn);
			return;
		}

		tcp_splice_state(conn, SPLICE_ESTABLISHED);

		ev_from.events = ev_to.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
		ev_from.data.u64 = ref_from.u64;
		ev_to.data.u64 = ref_to.u64;

		epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->from, &ev_from);
		epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->to, &ev_to);
	}

	conn->pipe_from_to[0] = conn->pipe_to_from[0] = -1;
	if (pipe2(conn->pipe_to_from, O_NONBLOCK) ||
	    pipe2(conn->pipe_from_to, O_NONBLOCK)) {
		tcp_splice_destroy(c, conn);
		return;
	}

	fcntl(conn->pipe_from_to[0], F_SETPIPE_SZ, PIPE_SIZE);
	fcntl(conn->pipe_to_from[0], F_SETPIPE_SZ, PIPE_SIZE);
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
			      int v6, in_port_t port)
{
	int sock_conn = socket(v6 ? AF_INET6 : AF_INET,
			       SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	union epoll_ref ref_accept = { .proto = IPPROTO_TCP, .s = conn->from,
				       .tcp = { .splice = 1, .v6 = v6,
						.index = conn - ts } };
	union epoll_ref ref_conn = { .proto = IPPROTO_TCP, .s = sock_conn,
				     .tcp = { .splice = 1, .v6 = v6,
					      .index = conn - ts } };
	struct epoll_event ev_accept = { .events = EPOLLRDHUP | EPOLLET,
				       .data.u64 = ref_accept.u64 };
	struct epoll_event ev_conn = { .events = EPOLLRDHUP | EPOLLET,
				       .data.u64 = ref_conn.u64 };
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

	if (sock_conn < 0)
		return -errno;

	conn->to = sock_conn;

	setsockopt(conn->from, SOL_TCP, TCP_CORK,    &one, sizeof(one));
	setsockopt(conn->from, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(conn->to,   SOL_TCP, TCP_CORK,    &one, sizeof(one));
	setsockopt(conn->to,   SOL_TCP, TCP_NODELAY, &one, sizeof(one));

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
		ev_conn.events |= EPOLLOUT;
	} else {
		tcp_splice_state(conn, SPLICE_ESTABLISHED);
		tcp_splice_connect_finish(c, conn, v6);

		ev_conn.events |= EPOLLIN;
		ev_accept.events |= EPOLLIN;
	}

	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->from, &ev_accept);
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
	a->ret = tcp_splice_connect(a->c, a->conn, a->v6, a->port);
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
	char ns_fn_stack[NS_FN_STACK_SIZE];

	if (bitmap_isset(c->tcp.port_to_ns, port)) {
		clone(tcp_splice_connect_ns,
		      ns_fn_stack + sizeof(ns_fn_stack) / 2,
		      CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD,
		      (void *)&ns_arg);

		return ns_arg.ret;
	}

	return tcp_splice_connect(c, conn, v6, port);
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
	socklen_t sa_len;
	int s;

	if (c->tcp.tap_conn_count >= MAX_TAP_CONNS)
		return;

	sa_len = sizeof(sa);
	s = accept4(ref.s, (struct sockaddr *)&sa, &sa_len, SOCK_NONBLOCK);
	if (s < 0)
		return;

	conn = &tt[c->tcp.tap_conn_count++];
	ref_conn.tcp.index = conn - tt;
	ref_conn.s = conn->sock = s;

	if (ref.tcp.v6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;

		if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
			memcpy(&sa6->sin6_addr, &c->gw6, sizeof(c->gw6));

		memcpy(&conn->a.a6, &sa6->sin6_addr, sizeof(conn->a.a6));

		conn->sock_port = ntohs(sa6->sin6_port);
		conn->tap_port = ref.tcp.index;

		conn->seq_to_tap = tcp_seq_init(c, AF_INET6, &sa6->sin6_addr,
						conn->sock_port,
						conn->tap_port,
						now);

		tcp_hash_insert(c, conn, AF_INET6, &sa6->sin6_addr);
	} else {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;

		memset(&conn->a.a4.zero,   0, sizeof(conn->a.a4.zero));
		memset(&conn->a.a4.one, 0xff, sizeof(conn->a.a4.one));

		if (ntohl(sa4->sin_addr.s_addr) == INADDR_LOOPBACK ||
		    ntohl(sa4->sin_addr.s_addr) == INADDR_ANY)
			sa4->sin_addr.s_addr = c->gw4;

		memcpy(&conn->a.a4.a, &sa4->sin_addr, sizeof(conn->a.a4.a));

		conn->sock_port = ntohs(sa4->sin_port);
		conn->tap_port = ref.tcp.index;

		conn->seq_to_tap = tcp_seq_init(c, AF_INET, &sa4->sin_addr,
						conn->sock_port,
						conn->tap_port,
						now);

		tcp_hash_insert(c, conn, AF_INET, &sa4->sin_addr);
	}

	conn->seq_ack_from_tap = conn->seq_to_tap + 1;

	conn->tap_window = WINDOW_DEFAULT;
	conn->ws_allowed = 1;

	conn->ts_sock = conn->ts_tap = conn->ts_ack_tap = *now;

	bitmap_set(tcp_act, conn - tt);

	ev.events = EPOLLRDHUP;
	ev.data.u64 = ref_conn.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->sock, &ev);

	tcp_tap_state(conn, SOCK_SYN_SENT);
	tcp_send_to_tap(c, conn, SYN, NULL, 0);
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
	int move_from, move_to, *pipes;
	struct tcp_splice_conn *conn;

	if (ref.tcp.listen) {
		int s;

		if (c->tcp.splice_conn_count >= MAX_SPLICE_CONNS)
			return;

		if ((s = accept4(ref.s, NULL, NULL, SOCK_NONBLOCK)) < 0)
			return;

		conn = &ts[c->tcp.splice_conn_count++];
		conn->from = s;
		tcp_splice_state(conn, SPLICE_ACCEPTED);

		if (tcp_splice_new(c, conn, ref.tcp.v6, ref.tcp.index))
			tcp_splice_destroy(c, conn);

		return;
	}

	conn = &ts[ref.tcp.index];

	if (events & EPOLLRDHUP || events & EPOLLHUP || events & EPOLLERR) {
		tcp_splice_destroy(c, conn);
		return;
	}

	if (events & EPOLLOUT) {
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLET | EPOLLRDHUP,
			.data.u64 = ref.u64,
		};

		if (conn->state == SPLICE_CONNECT) {
			tcp_splice_connect_finish(c, conn, ref.tcp.v6);
			return;
		}

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

swap:
	while (1) {
		int retry_write = 1, no_read = 1;
		ssize_t ret, nr = 0, nw;

retry:
		ret = splice(move_from, NULL, pipes[1], NULL, PIPE_SIZE,
				SPLICE_F_MOVE);
		if (ret < 0) {
			if (errno == EAGAIN) {
				nr = PIPE_SIZE;
			} else {
				tcp_splice_destroy(c, conn);
				return;
			}
		} else if (!ret && no_read) {
			break;
		} else if (ret) {
			no_read = 0;
			nr += ret;
		}

		nw = splice(pipes[0], NULL, move_to, NULL, nr, SPLICE_F_MOVE);
		if (nw < 0) {
			if (errno == EAGAIN) {
				struct epoll_event ev = {
					.events = EPOLLIN | EPOLLOUT | EPOLLET |
						  EPOLLRDHUP
				};

				if (no_read)
					break;

				if (retry_write--)
					goto retry;

				ref.s = move_to;
				ev.data.u64 = ref.u64,
				epoll_ctl(c->epollfd, EPOLL_CTL_MOD, move_to,
					  &ev);
				break;
			}
			tcp_splice_destroy(c, conn);
			return;
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

	if (conn->state == LAST_ACK) {
		tcp_send_to_tap(c, conn, ACK, NULL, 0);
		tcp_tap_destroy(c, conn);
		return;
	}

	if (conn->state == SOCK_SYN_SENT) {
		/* This can only be a socket error or a shutdown from remote */
		tcp_rst(c, conn);
		return;
	}

	if (events & EPOLLERR) {
		if (conn->state != CLOSED)
			tcp_rst(c, conn);
		return;
	}

	if (events & EPOLLOUT) {	/* Implies TAP_SYN_SENT */
		tcp_connect_finish(c, conn, ref);
		return;
	}

	if (conn->state == ESTABLISHED)
		tcp_data_from_sock(c, conn, now);

	if (events & (EPOLLRDHUP | EPOLLHUP)) {
		if (conn->state == ESTABLISHED) {
			tcp_tap_state(conn, ESTABLISHED_SOCK_FIN);
			shutdown(conn->sock, SHUT_RD);
			tcp_data_from_sock(c, conn, now);
			tcp_send_to_tap(c, conn, FIN | ACK, NULL, 0);
		} else if (conn->state == FIN_WAIT_1) {
			tcp_tap_state(conn, FIN_WAIT_1_SOCK_FIN);
			shutdown(conn->sock, SHUT_RD);
			tcp_data_from_sock(c, conn, now);
			tcp_send_to_tap(c, conn, FIN | ACK, NULL, 0);
			tcp_sock_consume(conn, conn->seq_ack_from_tap);
		} else {
			tcp_tap_destroy(c, conn);
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
	union tcp_epoll_ref tref = { .listen = 1, .splice = 1 };
	struct ctx *c = (struct ctx *)arg;
	in_port_t port;

	ns_enter(c->pasta_pid);

	for (port = 0; !PORT_IS_EPHEMERAL(port); port++) {
		if (!bitmap_isset(c->tcp.port_to_init, port))
			continue;

		tref.index = port;

		if (c->v4) {
			tref.v6 = 0;
			sock_l4(c, AF_INET, IPPROTO_TCP, port, 1, tref.u32);
		}

		if (c->v6) {
			tref.v6 = 1;
			sock_l4(c, AF_INET6, IPPROTO_TCP, port, 1, tref.u32);
		}
	}

	return 0;
}

/**
 * tcp_sock_init() - Bind sockets for inbound connections, get key for sequence
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int tcp_sock_init(struct ctx *c)
{
	union tcp_epoll_ref tref = { .listen = 1 };
	char ns_fn_stack[NS_FN_STACK_SIZE];
	in_port_t port;

	getrandom(&c->tcp.hash_secret, sizeof(c->tcp.hash_secret), GRND_RANDOM);

	for (port = 0; !PORT_IS_EPHEMERAL(port); port++) {
		if (bitmap_isset(c->tcp.port_to_ns, port))
			tref.splice = 1;
		else if (bitmap_isset(c->tcp.port_to_tap, port))
			tref.splice = 0;
		else
			continue;

		tref.index = port;

		if (c->v4) {
			tref.v6 = 0;
			sock_l4(c, AF_INET, IPPROTO_TCP, port, tref.splice,
				tref.u32);
		}

		if (c->v6) {
			tref.v6 = 1;
			sock_l4(c, AF_INET6, IPPROTO_TCP, port, tref.splice,
				tref.u32);
		}
	}

	if (c->mode == MODE_PASTA) {
		clone(tcp_sock_init_ns, ns_fn_stack + sizeof(ns_fn_stack) / 2,
		      CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD,
		      (void *)c);
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
	int ack_tap_ms = timespec_diff_ms(ts, &conn->ts_ack_tap);
	int sock_ms = timespec_diff_ms(ts, &conn->ts_tap);
	int tap_ms = timespec_diff_ms(ts, &conn->ts_tap);

	switch (conn->state) {
	case SOCK_SYN_SENT:
	case TAP_SYN_RCVD:
		if (ack_tap_ms > SYN_TIMEOUT)
			tcp_rst(c, conn);

		break;
	case ESTABLISHED_SOCK_FIN:
		if (ack_tap_ms > FIN_TIMEOUT) {
			tcp_rst(c, conn);
			break;
		}
		/* Falls through */
	case ESTABLISHED:
		if (tap_ms > ACT_TIMEOUT && sock_ms > ACT_TIMEOUT) {
			tcp_rst(c, conn);
			break;
		}

		if (conn->seq_to_tap == conn->seq_ack_from_tap &&
		    conn->seq_from_tap == conn->seq_ack_to_tap) {
			conn->ts_sock = *ts;
			break;
		}

		if (sock_ms > ACK_INTERVAL) {
			if (conn->seq_from_tap > conn->seq_ack_to_tap)
				tcp_send_to_tap(c, conn, ACK, NULL, 0);
		}

		if (ack_tap_ms > ACK_TIMEOUT) {
			if (conn->seq_ack_from_tap < conn->seq_to_tap) {
				if (ack_tap_ms > 10 * ACK_TIMEOUT) {
					tcp_rst(c, conn);
					break;
				}

				conn->seq_to_tap = conn->seq_ack_from_tap;
				tcp_data_from_sock(c, conn, ts);
			}
		}

		if (conn->seq_from_tap == conn->seq_ack_to_tap)
			conn->ts_sock = *ts;

		break;
	case CLOSE_WAIT:
	case FIN_WAIT_1:
		if (sock_ms > FIN_TIMEOUT)
			tcp_rst(c, conn);
		break;
	case FIN_WAIT_1_SOCK_FIN:
		if (ack_tap_ms > FIN_TIMEOUT)
			tcp_rst(c, conn);
		break;
	case LAST_ACK:
		if (sock_ms > LAST_ACK_TIMEOUT)
			tcp_rst(c, conn);
		break;
	case TAP_SYN_SENT:
	case SPLICE_ACCEPTED:
	case SPLICE_CONNECT:
	case SPLICE_ESTABLISHED:
	case CLOSED:
		break;
	}
}

/**
 * tcp_timer() - Scan activity bitmap for sockets waiting for timed events
 * @c:		Execution context
 * @ts:		Timestamp from caller
 */
void tcp_timer(struct ctx *c, struct timespec *ts)
{
	long *word = (long *)tcp_act, tmp;
	unsigned int i;
	int n;

	for (i = 0; i < sizeof(tcp_act) / sizeof(long); i++, word++) {
		tmp = *word;
		while ((n = ffsl(tmp))) {
			int index = i * sizeof(long) * 8 + n - 1;

			tmp &= ~(1UL << (n - 1));
			tcp_timer_one(c, &tt[index], ts);
		}
	}
}

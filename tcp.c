// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *
 * tcp.c - TCP L2-L4 translation state machine
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 */

/**
 * DOC: Theory of Operation
 *
 *
 * Overview
 * --------
 *
 * This implementation maps TCP traffic between a single L2 interface (tap) and
 * native TCP (L4) sockets, mimicking and reproducing as closely as possible the
 * inferred behaviour of applications running on a guest, connected via said L2
 * interface. Four connection flows are supported:
 * - from the local host to the guest behind the tap interface:
 *   - this is the main use case for proxies in service meshes
 *   - we bind to all unbound local ports, and relay traffic between L4 sockets
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
 * of connections is defined by TCP_MAX_CONNS below (currently 256k, close to
 * the maximum amount of file descriptors typically available to a process on
 * Linux).
 *
 * While fragmentation and reassembly are not implemented, tracking of missing
 * segments and retransmissions needs to be, thus data needs to linger on
 * sockets as long as it's not acknowledged by the guest, and read using
 * MSG_PEEK into a single, preallocated static buffer sized to the maximum
 * supported window, 64MiB. This imposes a practical limitation on window
 * scaling, that is, the maximum factor is 1024. If a bigger window scaling
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
 * ports, listening sockets are opened and bound to all unbound ports on the
 * host, as far as process capabilities allow. This service needs to be started
 * after any application proxy that needs to bind to local ports.
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
 * Connection are tracked by the @tc array of struct tcp_conn, containing
 * addresses, ports, TCP states and parameters. This is statically allocated and
 * indices are the file descriptor numbers associated to inbound or outbound
 * sockets.
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
 * IPv4 and IPv6) are opened and bound to wildcard addresses. Some will fail to
 * bind (for low ports, or ports already bound, e.g. by a proxy). These are
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
 */

#define _GNU_SOURCE
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

#include "passt.h"
#include "tap.h"
#include "util.h"
#include "siphash.h"

/* Approximately maximum number of open descriptors per process */
#define MAX_CONNS			(1024 * 1024)

#define TCP_HASH_TABLE_LOAD		70		/* % */
#define TCP_HASH_TABLE_SIZE		(MAX_CONNS * 100 / TCP_HASH_TABLE_LOAD)

#define MAX_WS				10
#define MAX_WINDOW			(1 << (16 + (MAX_WS)))
#define MSS_DEFAULT			536
#define WINDOW_DEFAULT			14600		/* RFC 6928 */

#define SYN_TIMEOUT			240000		/* ms */
#define ACK_TIMEOUT			3000
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
};
#define TCP_STATE_STR_SIZE	(FIN_WAIT_1_SOCK_FIN + 1)

static char *tcp_state_str[TCP_STATE_STR_SIZE] __attribute((__unused__)) = {
	"CLOSED", "TAP_SYN_SENT", "SOCK_SYN_SENT", "TAP_SYN_RCVD",
	"ESTABLISHED", "ESTABLISHED_SOCK_FIN", "CLOSE_WAIT", "LAST_ACK",
	"FIN_WAIT_1", "FIN_WAIT_1_SOCK_FIN",
};

#define FIN		(1 << 0)
#define SYN		(1 << 1)
#define RST		(1 << 2)
#define ACK		(1 << 4)

#define OPT_EOL		0
#define OPT_NOP		1
#define OPT_MSS		2
#define OPT_MSS_LEN	4
#define OPT_WS		3
#define OPT_WS_LEN	3
#define OPT_SACKP	4
#define OPT_SACK	5
#define OPT_TS		8

struct tcp_conn;

/**
 * struct tcp_conn - Descriptor for a TCP connection
 * @next:		Pointer to next item in hash chain, if any
 * @sock:		Socket descriptor number
 * @hash_bucket:	Bucket index in socket lookup hash table
 * @a.a6:		IPv6 remote address, can be IPv4-mapped
 * @a.a4.zero:		Zero prefix for IPv4-mapped, see RFC 6890, Table 20
 * @a.a4.one:		Ones prefix for IPv4-mapped
 * @a.a4.a:		IPv4 address
 * @tap_port:		Guest-facing tap port
 * @sock_port:		Remote, socket-facing port
 * @s:			TCP connection state
 * @seq_to_tap:		Next sequence for packets to tap
 * @seq_ack_from_tap:	Last ACK number received from tap
 * @seq_from_tap:	Next sequence for packets from tap (not actually sent)
 * @seq_ack_to_tap:	Last ACK number sent to tap
 * @seq_init_from_tap:	Initial sequence number from tap
 * @tcpi_acked_last:	Most recent value of tcpi_bytes_acked (TCP_INFO query)
 * @dup_acks:		Count of currently duplicated ACKs from tap
 * @ws_allowed:		Window scaling allowed
 * @ws:			Window scaling factor
 * @tap_window:		Last window size received from tap, scaled
 * @no_snd_wnd:		Kernel won't report window (without commit 8f7baad7f035)
 * @ts_sock:		Last activity timestamp from socket for timeout purposes
 * @ts_tap:		Last activity timestamp from tap for timeout purposes
 * @ts_ack_tap:		Last ACK segment timestamp from tap for timeout purposes
 * @mss_guest:		Maximum segment size advertised by guest
 */
struct tcp_conn {
	struct tcp_conn *next;
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
	enum tcp_state s;

	uint32_t seq_to_tap;
	uint32_t seq_ack_from_tap;
	uint32_t seq_from_tap;
	uint32_t seq_ack_to_tap;
	uint32_t seq_init_from_tap;
	uint64_t tcpi_acked_last;
	int dup_acks;

	int ws_allowed;
	int ws;
	int tap_window;
	int no_snd_wnd;

	struct timespec ts_sock;
	struct timespec ts_tap;
	struct timespec ts_ack_tap;

	int mss_guest;
};

/* Socket receive buffer */
static char sock_buf[MAX_WINDOW];

/* Bitmap, activity monitoring needed for connection, indexed by socket */
static uint8_t tcp_act[MAX_CONNS / 8] = { 0 };

/* TCP connections, indexed by socket */
static struct tcp_conn tc[MAX_CONNS];

/* Hash table for socket lookup given remote address, local port, remote port */
static int tc_hash[TCP_HASH_TABLE_SIZE];

static int tcp_send_to_tap(struct ctx *c, int s, int flags, char *in, int len);

/**
 * tcp_act_set() - Set socket in bitmap for timed events
 * @s:		Socket file descriptor number
 */
static void tcp_act_set(int s)
{
	tcp_act[s / 8] |= 1 << (s % 8);
}

/**
 * tcp_act_clear() - Clear socket from bitmap for timed events
 * @s:		Socket file descriptor number
 */
static void tcp_act_clear(int s)
{
	tcp_act[s / 8] &= ~(1 << (s % 8));
}

/**
 * tcp_set_state() - Set given TCP state for socket, report change to stderr
 * @s:		Socket file descriptor number
 * @state:	New TCP state to be set
 */
static void tcp_set_state(int s, enum tcp_state state)
{
	debug("TCP: socket %i: %s -> %s", s,
	      tcp_state_str[tc[s].s], tcp_state_str[state]);
	tc[s].s = state;
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
 * tcp_sock_hash_match() - Check if a connection entry matches address and ports
 * @conn:	Connection entry to match against
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: 1 on match, 0 otherwise
 */
static int tcp_sock_hash_match(struct tcp_conn *conn, int af, void *addr,
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
 * tcp_sock_hash() - Calculate hash value for connection given address and ports
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: hash value, already modulo size of the hash table
 */
static unsigned int tcp_sock_hash(struct ctx *c, int af, void *addr,
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
 * tcp_sock_hash_insert() - Insert socket into hash table, chain link if needed
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 */
static void tcp_sock_hash_insert(struct ctx *c, int s, int af, void *addr,
				 in_port_t tap_port, in_port_t sock_port)
{
	int b;

	b = tcp_sock_hash(c, af, addr, tap_port, sock_port);
	tc[s].next = tc_hash[b] ? &tc[tc_hash[b]] : NULL;
	tc_hash[b] = tc[s].sock = s;
	tc[s].hash_bucket = b;
}

/**
 * tcp_sock_hash_remove() - Drop socket from hash table, chain unlink if needed
 * @b:		Bucket index
 * @s:		File descriptor number for socket
 */
static void tcp_sock_hash_remove(int b, int s)
{
	struct tcp_conn *conn, *prev = NULL;

	for (conn = &tc[tc_hash[b]]; conn; prev = conn, conn = conn->next) {
		if (conn->sock == s) {
			conn->sock = 0;
			if (prev)
				prev->next = conn->next;
			else
				tc_hash[b] = conn->next ? conn->next->sock : 0;
			return;
		}
	}
}

/**
 * tcp_sock_hash_lookup() - Look up socket given remote address and ports
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: file descriptor number for socket, if found, -ENOENT otherwise
 */
static int tcp_sock_hash_lookup(struct ctx *c, int af, void *addr,
				in_port_t tap_port, in_port_t sock_port)
{
	struct tcp_conn *conn;
	int b;

	b = tcp_sock_hash(c, af, addr, tap_port, sock_port);
	if (!tc_hash[b])
		return -ENOENT;

	for (conn = &tc[tc_hash[b]]; conn; conn = conn->next) {
		if (tcp_sock_hash_match(conn, af, addr, tap_port, sock_port))
			return conn->sock;
	}

	return -ENOENT;
}

/**
 * tcp_close_and_epoll_del() - Close, remove socket from hash table and epoll fd
 * @c:		Execution context
 * @s:		File descriptor number for socket
 */
static void tcp_close_and_epoll_del(struct ctx *c, int s)
{
	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, s, NULL);
	tcp_set_state(s, CLOSED);
	close(s);
	tcp_sock_hash_remove(tc[s].hash_bucket, tc[s].sock);
	tcp_act_clear(s);
}

/**
 * tcp_rst() - Reset a connection: send RST segment to tap, close socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 */
static void tcp_rst(struct ctx *c, int s)
{
	if (s < 0)
		return;

	tcp_send_to_tap(c, s, RST, NULL, 0);
	tcp_close_and_epoll_del(c, s);
	tcp_set_state(s, CLOSED);
}

/**
 * tcp_send_to_tap() - Send segment to tap, with options and values from socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @flags:	TCP flags to set
 * @in:		Payload buffer
 * @len:	Payload length
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
static int tcp_send_to_tap(struct ctx *c, int s, int flags, char *in, int len)
{
	char buf[USHRT_MAX] = { 0 }, *data;
	struct tcp_info info = { 0 };
	socklen_t sl = sizeof(info);
	struct tcphdr *th;
	int ws = 0, err;

	if ((err = getsockopt(s, SOL_TCP, TCP_INFO, &info, &sl)) &&
	    !(flags & RST)) {
		tcp_rst(c, s);
		return err;
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
		tc[s].no_snd_wnd = !info.tcpi_snd_wnd;

		if (tc[s].ws_allowed && (ws = info.tcpi_snd_wscale) &&
		    !tc[s].no_snd_wnd) {
			*data++ = OPT_NOP;

			*data++ = OPT_WS;
			*data++ = OPT_WS_LEN;
			*data++ = ws;

			th->doff += (1 + OPT_WS_LEN) / 4;
		}

		/* RFC 793, 3.1: "[...] and the first data octet is ISN+1." */
		th->seq = htonl(tc[s].seq_to_tap++);
	} else {
		th->seq = htonl(tc[s].seq_to_tap);
		tc[s].seq_to_tap += len;
	}

	if (!err && ((info.tcpi_bytes_acked > tc[s].tcpi_acked_last) ||
		     (flags & ACK) || len)) {
		uint64_t ack_seq;

		th->ack = 1;

		ack_seq = info.tcpi_bytes_acked + tc[s].seq_init_from_tap;

		tc[s].seq_ack_to_tap = ack_seq & (uint32_t)~0U;

		if (tc[s].s == LAST_ACK) {
			tc[s].seq_ack_to_tap = tc[s].seq_from_tap + 1;
			th->seq = htonl(ntohl(th->seq) + 1);
		}

		th->ack_seq = htonl(tc[s].seq_ack_to_tap);

		tc[s].tcpi_acked_last = info.tcpi_bytes_acked;
	} else {
		if (!len && !flags)
			return 0;

		th->ack = th->ack_seq = 0;
	}

	th->rst = !!(flags & RST);
	th->syn = !!(flags & SYN);
	th->fin = !!(flags & FIN);

	th->source = tc[s].sock_port;
	th->dest = tc[s].tap_port;

	if (!err && !tc[s].no_snd_wnd) {
		/* First value sent by receiver is not scaled */
		th->window = htons(info.tcpi_snd_wnd >>
				   (th->syn ? 0 : info.tcpi_snd_wscale));
	} else {
		th->window = htons(WINDOW_DEFAULT);
	}

	th->urg_ptr = 0;
	th->check = 0;

	memcpy(data, in, len);

	tap_ip_send(c, &tc[s].a.a6, IPPROTO_TCP, buf, th->doff * 4 + len);

	return 0;
}

/**
 * tcp_clamp_window() - Set window and scaling from option, clamp on socket
 * @s:		File descriptor number for socket
 * @th:		TCP header, from tap
 * @len:	Buffer length, at L4
 * @init:	Set if this is the very first segment from tap
 */
static void tcp_clamp_window(int s, struct tcphdr *th, int len, int init)
{
	if (init) {
		tc[s].ws = tcp_opt_get(th, len, OPT_WS, NULL, NULL);
		tc[s].ws_allowed = tc[s].ws >= 0 && tc[s].ws <= MAX_WS;
		tc[s].ws *= tc[s].ws_allowed;

		/* RFC 7323, 2.2: first value is not scaled. Also, don't clamp
		 * yet, to avoid getting a zero scale just because we set a
		 * small window now.
		 */
		tc[s].tap_window = ntohs(th->window);
	} else {
		tc[s].tap_window = ntohs(th->window) << tc[s].ws;
		setsockopt(s, SOL_TCP, TCP_WINDOW_CLAMP,
			   &tc[s].tap_window, sizeof(tc[s].tap_window));
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
	struct epoll_event ev = { 0 };
	const struct sockaddr *sa;
	socklen_t sl;
	int s;

	s = socket(af, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (s < 0)
		return;

	if (s >= MAX_CONNS) {
		close(s);
		return;
	}

	tc[s].mss_guest = tcp_opt_get(th, len, OPT_MSS, NULL, NULL);
	if (tc[s].mss_guest < 0)
		tc[s].mss_guest = MSS_DEFAULT;
	sl = sizeof(tc[s].mss_guest);
	setsockopt(s, SOL_TCP, TCP_MAXSEG, &tc[s].mss_guest, sl);

	tcp_clamp_window(s, th, len, 1);

	if (af == AF_INET) {
		sa = (struct sockaddr *)&addr4;
		sl = sizeof(addr4);

		memset(&tc[s].a.a4.zero, 0,    sizeof(tc[s].a.a4.zero));
		memset(&tc[s].a.a4.one,  0xff, sizeof(tc[s].a.a4.one));
		memcpy(&tc[s].a.a4.a,    addr, sizeof(tc[s].a.a4.a));
	} else {
		sa = (struct sockaddr *)&addr6;
		sl = sizeof(addr6);

		memcpy(&tc[s].a.a6,      addr, sizeof(tc[s].a.a6));
	}

	tc[s].sock_port = th->dest;
	tc[s].tap_port = th->source;

	tc[s].ts_sock = tc[s].ts_tap = tc[s].ts_ack_tap = *now;

	tcp_act_set(s);

	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP;
	ev.data.fd = s;

	tc[s].seq_init_from_tap = ntohl(th->seq);
	tc[s].seq_from_tap = tc[s].seq_init_from_tap + 1;
	tc[s].seq_ack_to_tap = tc[s].seq_from_tap;

	tc[s].seq_to_tap = tcp_seq_init(c, af, addr, th->dest, th->source, now);
	tc[s].seq_ack_from_tap = tc[s].seq_to_tap + 1;

	tcp_sock_hash_insert(c, s, af, addr, th->source, th->dest);

	if (connect(s, sa, sl)) {
		if (errno != EINPROGRESS) {
			tcp_rst(c, s);
			return;
		}

		ev.events |= EPOLLOUT;
		tcp_set_state(s, TAP_SYN_SENT);
	} else {
		if (tcp_send_to_tap(c, s, SYN | ACK, NULL, 0))
			return;

		tcp_set_state(s, TAP_SYN_RCVD);
	}

	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, s, &ev);
}

/**
 * tcp_conn_from_sock() - Handle new connection request from listening socket
 * @c:		Execution context
 * @fd:		File descriptor number for listening socket
 * @now:	Current timestamp
 */
static void tcp_conn_from_sock(struct ctx *c, int fd, struct timespec *now)
{
	struct sockaddr_storage sa_r, sa_l;
	socklen_t sa_len = sizeof(sa_l);
	struct epoll_event ev = { 0 };
	int s;

	if (getsockname(fd, (struct sockaddr *)&sa_l, &sa_len))
		return;

	s = accept4(fd, (struct sockaddr *)&sa_r, &sa_len, SOCK_NONBLOCK);
	if (s == -1)
		return;

	if (s >= MAX_CONNS) {
		close(s);
		return;
	}

	CHECK_SET_MIN_MAX(c->tcp.fd_, s);
	CHECK_SET_MIN_MAX(c->tcp.fd_conn_, s);

	if (sa_l.ss_family == AF_INET) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa_r;

		memset(&tc[s].a.a4.zero, 0, sizeof(tc[s].a.a4.zero));
		memset(&tc[s].a.a4.one, 0xff, sizeof(tc[s].a.a4.one));

		if (ntohl(sa4->sin_addr.s_addr) == INADDR_LOOPBACK ||
		    ntohl(sa4->sin_addr.s_addr) == INADDR_ANY)
			sa4->sin_addr.s_addr = c->gw4;

		memcpy(&tc[s].a.a4.a, &sa4->sin_addr, sizeof(tc[s].a.a4.a));

		tc[s].sock_port = sa4->sin_port;
		tc[s].tap_port = ((struct sockaddr_in *)&sa_l)->sin_port;

		tc[s].seq_to_tap = tcp_seq_init(c, AF_INET, &sa4->sin_addr,
						tc[s].sock_port,
						tc[s].tap_port,
						now);

		tcp_sock_hash_insert(c, s, AF_INET, &sa4->sin_addr,
				     tc[s].tap_port, tc[s].sock_port);
	} else if (sa_l.ss_family == AF_INET6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa_r;

		if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
			memcpy(&sa6->sin6_addr, &c->gw6, sizeof(c->gw6));

		memcpy(&tc[s].a.a6, &sa6->sin6_addr, sizeof(tc[s].a.a6));

		tc[s].sock_port = sa6->sin6_port;
		tc[s].tap_port = ((struct sockaddr_in6 *)&sa_l)->sin6_port;

		tc[s].seq_to_tap = tcp_seq_init(c, AF_INET6, &sa6->sin6_addr,
						tc[s].sock_port,
						tc[s].tap_port,
						now);

		tcp_sock_hash_insert(c, s, AF_INET6, &sa6->sin6_addr,
				     tc[s].tap_port, tc[s].sock_port);
	}

	tc[s].seq_ack_from_tap = tc[s].seq_to_tap + 1;

	tc[s].tap_window = WINDOW_DEFAULT;
	tc[s].ws_allowed = 1;

	tc[s].ts_sock = tc[s].ts_tap = tc[s].ts_ack_tap = *now;

	tcp_act_set(s);

	ev.events = EPOLLRDHUP | EPOLLHUP;
	ev.data.fd = s;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, s, &ev);

	tcp_set_state(s, SOCK_SYN_SENT);
	tcp_send_to_tap(c, s, SYN, NULL, 0);
}

/**
 * tcp_send_to_sock() - Send buffer to socket, update timestamp and sequence
 * @c:			Execution context
 * @s:			File descriptor number for socket
 * @data:		Data buffer
 * @len:		Length at L4
 * @extra_flags:	Additional flags for send(), if any
 *
 * Return: negative on socket error with connection reset, 0 otherwise
 */
static int tcp_send_to_sock(struct ctx *c, int s, char *data, int len,
			    int extra_flags)
{
	int err = send(s, data, len, MSG_DONTWAIT | MSG_NOSIGNAL | extra_flags);

	if (err < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* If we can't queue right now, do nothing, sender has
			 * to retransmit.
			 */
			return 0;
		}

		err = errno;
		tcp_rst(c, s);
		return -err;
	}

	tc[s].seq_from_tap += len;

	return 0;
}

/**
 * tcp_is_dupack() - Check if given ACK number is duplicated, update counter
 * @s:		File descriptor number for socket
 * @ack_seq:	ACK sequence, host order
 *
 * Return: -EAGAIN on duplicated ACKs observed, with counter reset, 0 otherwise
 */
static int tcp_is_dupack(int s, uint32_t ack_seq)
{
	if (ack_seq == tc[s].seq_ack_from_tap && ++tc[s].dup_acks == 2) {
		tc[s].dup_acks = 0;
		return -EAGAIN;
	}

	return 0;
}

/**
 * tcp_sock_consume() - Consume (discard) data from buffer, update ACK sequence
 * @s:		File descriptor number for socket
 * @ack_seq:	ACK sequence, host order
 */
static void tcp_sock_consume(int s, uint32_t ack_seq)
{
	int to_ack;

	/* Implicitly take care of wrap-arounds */
	to_ack = ack_seq - tc[s].seq_ack_from_tap;

	/* Simply ignore out-of-order ACKs: we already consumed the data we
	 * needed from the buffer, and we won't rewind back to a lower ACK
	 * sequence.
	 */
	if (to_ack < 0)
		return;

	recv(s, NULL, to_ack, MSG_DONTWAIT | MSG_TRUNC);

	tc[s].seq_ack_from_tap = ack_seq;
}

/**
 * tcp_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @now:	Current timestamp
 *
 * Return: negative on connection reset, 1 on pending data, 0 otherwise
 */
static int tcp_data_from_sock(struct ctx *c, int s, struct timespec *now)
{
	int len, err, offset, left, send;

	/* Don't dequeue until acknowledged by guest */
	len = recv(s, sock_buf, sizeof(sock_buf), MSG_DONTWAIT | MSG_PEEK);
	if (len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			tcp_rst(c, s);
			return -errno;
		}
		return 0;
	}

	if (len == 0) {
		if (tc[s].s >= ESTABLISHED_SOCK_FIN)
			return 0;

		tcp_set_state(s, ESTABLISHED_SOCK_FIN);
		if ((err = tcp_send_to_tap(c, s, FIN | ACK, NULL, 0)))
			return err;

		left = 0;
		goto out;
	}

	offset = tc[s].seq_to_tap - tc[s].seq_ack_from_tap;
	left = len - offset;
	while (left && offset + tc[s].mss_guest <= tc[s].tap_window) {
		if (left < tc[s].mss_guest)
			send = left;
		else
			send = tc[s].mss_guest;

		if ((err = tcp_send_to_tap(c, s, 0, sock_buf + offset, send)))
			return err;

		offset += send;
		left -= send;
	}

out:
	tc[s].ts_sock = *now;

	return !!left;
}

/**
 * tcp_tap_handler() - Handle packets from tap and state transitions
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @msg:	Input messages
 * @count:	Message count
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 */
int tcp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count, struct timespec *now)
{
	/* TODO: Implement message batching for TCP */
	struct tcphdr *th = (struct tcphdr *)msg[0].l4h;
	struct epoll_event ev = { 0 };
	size_t len = msg[0].l4_len;

	size_t off, skip = 0;
	int s, ws;

	(void)count;

	if (len < sizeof(*th))
		return 1;

	off = th->doff * 4;
	if (off < sizeof(*th) || off > len)
		return 1;

	if ((s = tcp_sock_hash_lookup(c, af, addr, th->source, th->dest)) < 0) {
		if (th->syn)
			tcp_conn_from_tap(c, af, addr, th, len, now);
		return 1;
	}

	if (th->rst) {
		tcp_close_and_epoll_del(c, s);
		return 1;
	}

	tcp_clamp_window(s, th, len, th->syn && th->ack);

	tc[s].ts_tap = *now;

	if (ntohl(th->seq) < tc[s].seq_from_tap)
		skip = tc[s].seq_from_tap - ntohl(th->seq);

	switch (tc[s].s) {
	case SOCK_SYN_SENT:
		if (!th->syn || !th->ack) {
			tcp_rst(c, s);
			return 1;
		}

		tc[s].mss_guest = tcp_opt_get(th, len, OPT_MSS, NULL, NULL);
		if (tc[s].mss_guest < 0)
			tc[s].mss_guest = MSS_DEFAULT;

		ws = tcp_opt_get(th, len, OPT_WS, NULL, NULL);
		if (ws > MAX_WS) {
			if (tcp_send_to_tap(c, s, RST, NULL, 0))
				return 1;

			tc[s].seq_to_tap = 0;
			tc[s].ws_allowed = 0;
			tcp_send_to_tap(c, s, SYN, NULL, 0);
			return 1;
		}

		/* info.tcpi_bytes_acked already includes one byte for SYN, but
		 * not for incoming connections.
		 */
		tc[s].seq_init_from_tap = ntohl(th->seq) + 1;
		tc[s].seq_from_tap = tc[s].seq_init_from_tap;
		tc[s].seq_ack_to_tap = tc[s].seq_from_tap;

		tcp_set_state(s, ESTABLISHED);
		tcp_send_to_tap(c, s, ACK, NULL, 0);

		/* The client might have sent data already, which we didn't
		 * dequeue waiting for SYN,ACK from tap -- check now.
		 */
		tcp_data_from_sock(c, s, now);

		ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP;
		ev.data.fd = s;
		epoll_ctl(c->epollfd, EPOLL_CTL_MOD, s, &ev);

		break;
	case TAP_SYN_RCVD:
		if (th->fin) {
			shutdown(s, SHUT_WR);
			tcp_set_state(s, FIN_WAIT_1);
			break;
		}

		if (!th->ack) {
			tcp_rst(c, s);
			return 1;
		}

		tcp_set_state(s, ESTABLISHED);
		break;
	case ESTABLISHED:
	case ESTABLISHED_SOCK_FIN:
		tc[s].ts_ack_tap = *now;

		if (ntohl(th->seq) > tc[s].seq_from_tap) {
			tc[s].seq_from_tap = tc[s].seq_ack_to_tap;
			tcp_send_to_tap(c, s, ACK, NULL, 0);
			break;
		}

		if (th->ack) {
			int retrans = 0;

			if (len == off)
				retrans = tcp_is_dupack(s, ntohl(th->ack_seq));

			tcp_sock_consume(s, ntohl(th->ack_seq));

			if (retrans)
				tc[s].seq_to_tap = tc[s].seq_ack_from_tap;

			if (tc[s].s == ESTABLISHED_SOCK_FIN) {
				if (!tcp_data_from_sock(c, s, now))
					tcp_set_state(s, CLOSE_WAIT);
			}
		}

		if (skip < len - off &&
		    tcp_send_to_sock(c, s,
				     msg[0].l4h + off + skip, len - off - skip,
				     th->psh ? 0 : MSG_MORE))
			break;

		tcp_data_from_sock(c, s, now);

		if (th->fin) {
			shutdown(s, SHUT_WR);
			if (tc[s].s == ESTABLISHED)
				tcp_set_state(s, FIN_WAIT_1);
			else
				tcp_set_state(s, LAST_ACK);
		}

		break;
	case CLOSE_WAIT:
		tcp_sock_consume(s, ntohl(th->ack_seq));

		if (skip < len - off &&
		    tcp_send_to_sock(c, s,
				     msg[0].l4h + off + skip, len - off - skip,
				     th->psh ? 0 : MSG_MORE))
			break;

		if (th->fin) {
			shutdown(s, SHUT_WR);
			tcp_set_state(s, LAST_ACK);
		}

		break;
	case FIN_WAIT_1_SOCK_FIN:
		if (th->ack)
			tcp_close_and_epoll_del(c, s);
		break;
	case FIN_WAIT_1:
	case TAP_SYN_SENT:
	case LAST_ACK:
	case CLOSED:	/* ;) */
		break;
	}

	return 1;
}

/**
 * tcp_connect_finish() - Handle completion of connect() from EPOLLOUT event
 * @c:		Execution context
 * @s:		File descriptor number for socket
 */
static void tcp_connect_finish(struct ctx *c, int s)
{
	struct epoll_event ev = { 0 };
	socklen_t sl;
	int so;

	sl = sizeof(so);
	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &so, &sl) || so) {
		tcp_rst(c, s);
		return;
	}

	if (tcp_send_to_tap(c, s, SYN | ACK, NULL, 0))
		return;

	/* Drop EPOLLOUT, only used to wait for connect() to complete */
	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP;
	ev.data.fd = s;
	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, s, &ev);

	tcp_set_state(s, TAP_SYN_RCVD);
}

/**
 * tcp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @events:	epoll events bitmap
 * @pkt_buf:	Buffer to receive packets, currently unused
 * @now:	Current timestamp
 */
void tcp_sock_handler(struct ctx *c, int s, uint32_t events, char *pkt_buf,
		      struct timespec *now)
{
	int accept = -1;
	socklen_t sl;

	(void)pkt_buf;

	sl = sizeof(accept);

	if (tc[s].s == LAST_ACK) {
		tcp_send_to_tap(c, s, ACK, NULL, 0);
		tcp_close_and_epoll_del(c, s);
		return;
	}

	if (tc[s].s == SOCK_SYN_SENT) {
		/* This can only be a socket error or a shutdown from remote */
		tcp_rst(c, s);
		return;
	}
	if (IN_INTERVAL(c->tcp.fd_listen_min, c->tcp.fd_listen_max, s) &&
	    !IN_INTERVAL(c->tcp.fd_conn_min, c->tcp.fd_conn_max, s))
		accept = 1;
	else if (IN_INTERVAL(c->tcp.fd_conn_min, c->tcp.fd_conn_max, s) &&
		 !IN_INTERVAL(c->tcp.fd_listen_min, c->tcp.fd_listen_max, s))
		accept = 0;
	else if (getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, &accept, &sl))
		accept = -1;

	if ((events & EPOLLERR) || accept == -1) {
		if (tc[s].s != CLOSED)
			tcp_rst(c, s);
		return;
	}

	if (accept) {
		tcp_conn_from_sock(c, s, now);
		return;
	}

	if (events & EPOLLOUT) {	/* Implies TAP_SYN_SENT */
		tcp_connect_finish(c, s);
		return;
	}

	if (tc[s].s == ESTABLISHED)
		tcp_data_from_sock(c, s, now);

	if (events & EPOLLRDHUP || events & EPOLLHUP) {
		if (tc[s].s == ESTABLISHED) {
			tcp_set_state(s, ESTABLISHED_SOCK_FIN);
			shutdown(s, SHUT_RD);
			tcp_data_from_sock(c, s, now);
			tcp_send_to_tap(c, s, FIN | ACK, NULL, 0);
		} else if (tc[s].s == FIN_WAIT_1) {
			tcp_set_state(s, FIN_WAIT_1_SOCK_FIN);
			shutdown(s, SHUT_RD);
			tcp_data_from_sock(c, s, now);
			tcp_send_to_tap(c, s, FIN | ACK, NULL, 0);
			tcp_sock_consume(s, tc[s].seq_ack_from_tap);
		} else {
			tcp_close_and_epoll_del(c, s);
		}
	}
}

/**
 * tcp_sock_init() - Bind sockets for inbound connections, get key for sequence
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int tcp_sock_init(struct ctx *c)
{
	in_port_t port;
	int s = 0;

	c->tcp.fd_min = c->tcp.fd_listen_min = c->tcp.fd_conn_min = INT_MAX;
	c->tcp.fd_max = c->tcp.fd_listen_max = c->tcp.fd_conn_max = 0;
	CHECK_SET_MIN_MAX(c->tcp.fd_listen_, s);

	for (port = 0; !PORT_IS_EPHEMERAL(port); port++) {
		if (c->v4) {
			if ((s = sock_l4(c, AF_INET, IPPROTO_TCP, port)) < 0)
				return -1;
			CHECK_SET_MIN_MAX(c->tcp.fd_listen_, s);
		}

		if (c->v6) {
			if ((s = sock_l4(c, AF_INET6, IPPROTO_TCP, port)) < 0)
				return -1;
			CHECK_SET_MIN_MAX(c->tcp.fd_listen_, s);
		}
	}

	getrandom(&c->tcp.hash_secret, sizeof(c->tcp.hash_secret), GRND_RANDOM);

	return 0;
}

/**
 * tcp_timer_one() - Handler for timed events on one socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @ts:		Timestamp from caller
 */
static void tcp_timer_one(struct ctx *c, int s, struct timespec *ts)
{
	int ack_tap_ms = timespec_diff_ms(ts, &tc[s].ts_ack_tap);
	int sock_ms = timespec_diff_ms(ts, &tc[s].ts_tap);
	int tap_ms = timespec_diff_ms(ts, &tc[s].ts_tap);

	switch (tc[s].s) {
	case SOCK_SYN_SENT:
	case TAP_SYN_RCVD:
		if (ack_tap_ms > SYN_TIMEOUT)
			tcp_rst(c, s);

		break;
	case ESTABLISHED_SOCK_FIN:
		if (ack_tap_ms > FIN_TIMEOUT) {
			tcp_rst(c, s);
			break;
		}
		/* Falls through */
	case ESTABLISHED:
		if (tap_ms > ACT_TIMEOUT && sock_ms > ACT_TIMEOUT)
			tcp_rst(c, s);

		if (tc[s].seq_to_tap == tc[s].seq_ack_from_tap &&
		    tc[s].seq_from_tap == tc[s].seq_ack_to_tap) {
			tc[s].ts_sock = *ts;
			break;
		}

		if (sock_ms > ACK_INTERVAL) {
			if (tc[s].seq_from_tap > tc[s].seq_ack_to_tap)
				tcp_send_to_tap(c, s, 0, NULL, 0);
		}

		if (ack_tap_ms > ACK_TIMEOUT) {
			if (tc[s].seq_ack_from_tap < tc[s].seq_to_tap) {
				tc[s].seq_to_tap = tc[s].seq_ack_from_tap;
				tc[s].ts_ack_tap = *ts;
				tcp_data_from_sock(c, s, ts);
			}
		}

		if (tc[s].seq_from_tap == tc[s].seq_ack_to_tap)
			tc[s].ts_sock = *ts;

		break;
	case CLOSE_WAIT:
	case FIN_WAIT_1:
		if (sock_ms > FIN_TIMEOUT)
			tcp_rst(c, s);
		break;
	case FIN_WAIT_1_SOCK_FIN:
		if (ack_tap_ms > FIN_TIMEOUT)
			tcp_rst(c, s);
		break;
	case LAST_ACK:
		if (sock_ms > LAST_ACK_TIMEOUT)
			tcp_rst(c, s);
		break;
	case TAP_SYN_SENT:
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
			tmp &= ~(1UL << (n - 1));
			tcp_timer_one(c, i * sizeof(long) * 8 + n - 1, ts);
		}
	}
}

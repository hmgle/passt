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
 * both sides of the connection, and most states are omitted as they are already
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
 *   - SYN,ACK timeout		RST to tap, close socket > CLOSED
 *   - socket error		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 *
 * - TAP_SYN_RCVD		connect() completed, SYN,ACK sent to tap
 *   - ACK from tap		> ESTABLISHED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *   - socket error		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 *
 * - ESTABLISHED		connection established, ready for data
 *   - zero-sized socket read	FIN to tap > ESTABLISHED_SOCK_FIN
 *   - data timeout		FIN to tap > ESTABLISHED_SOCK_FIN
 *   - socket error		RST to tap, close socket > CLOSED
 *   - FIN from tap		FIN,ACK to tap, close socket > FIN_WAIT_1
 *   - RST from tap		close socket > CLOSED
 *
 * - ESTABLISHED_SOCK_FIN	socket wants to close connection, data allowed
 *   - ACK from tap		> CLOSE_WAIT
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 *
 * - CLOSE_WAIT			socket wants to close connection, seen by tap
 *   - socket error		RST to tap, close socket > CLOSED
 *   - FIN from tap		ACK to tap, close socket > LAST_ACK
 *   - FIN timeout		RST to tap, close socket > CLOSED
 *   - RST from tap		close socket > CLOSED
 * 
 * - LAST_ACK			socket started close, tap completed it
 *   - anything from socket	close socket > CLOSED
 *   - socket error		RST to tap, close socket > CLOSED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *
 * - FIN_WAIT_1			tap wants to close connection, _FIN,ACK sent_
 *   - ACK from tap		close socket > CLOSED
 *   - socket error		RST to tap, close socket > CLOSED
 *   - ACK timeout		RST to tap, close socket > CLOSED
 *
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
 * Two bitmaps of TCP_MAX_CONNS bits indicate which connections need scheduled
 * actions:
 * - @tcp_act_fast is used to send ACK segments to the tap once TCP_INFO reports
 *   an increased number of acknowledged bytes sent on a socket, and examined
 *   every 20ms (one tenth of current TCP_DELACK_MAX on Linux): for each marked
 *   connection, a TCP_INFO query is performed and ACK segments are sent right
 *   away as needed
 * - @tcp_act_slow is used for state and retransmission timeouts, and examined
 *   every 2s: for each marked connection with an expired @timeout timestamp
 *   specific actions are taken depending on the connection state:
 *   - SOCK_SYN_SENT: after a 2MSL (240s) timeout waiting for a SYN,ACK segment
 *     from tap expires, connection is reset (RST to tap, socket closed)
 *   - TAP_SYN_RCVD: after a 2MSL (240s) timeout waiting for an ACK segment from
 *     tap expires, connection is reset (RST to tap, socket closed)
 *   - ESTABLISHED: after a timeout of 1s (TODO: implement requirements from
 *     RFC 6298) waiting for an ACK segment from tap expires, data from socket
 *     queue is retransmitted starting from the last ACK sequence
 *   - ESTABLISHED: after a two hours (current TCP_KEEPALIVE_TIME on Linux)
 *     timeout waiting for any activity expires, connection is reset (RST to
 *     tap, socket closed)
 *   - ESTABLISHED_SOCK_FIN: after a 2MSL (240s) timeout waiting for an ACK
 *     segment from tap expires, connection is reset (RST to tap, socket closed)
 *   - CLOSE_WAIT: after a 2MSL (240s) timeout waiting for a FIN segment from
 *     tap expires, connection is reset (RST to tap, socket closed)
 *   - LAST_ACK: after a 2MSL (240s) timeout waiting for an ACK segment from
 *     socket expires, connection is reset (RST to tap, socket closed)
 *   - FIN_WAIT_1: after a 2MSL (240s) timeout waiting for an ACK segment from
 *     tap expires, connection is reset (RST to tap, socket closed)
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
 *       @last_ts_to_tap elapsed, reset @seq_to_tap to @seq_ack_from_tap, and
 *       resend data with the steps listed above
 *
 * - from tap to socket:
 *   - on packet from tap:
 *     - set TCP_WINDOW_CLAMP from TCP header from tap
 *     - check seq from header against @seq_from_tap, if data is missing, send
 *       two ACKs with number @seq_ack_to_tap, discard packet
 *     - otherwise queue data to socket, set @seq_from_tap to seq from header
 *       plus payload length
 *     - query socket for TCP_INFO, on tcpi_bytes_acked > @tcpi_acked_last,
 *       set @tcpi_acked_last to tcpi_bytes_acked, set @seq_ack_to_tap
 *       to (tcpi_bytes_acked + @seq_init_from_tap) % 2^32 and
 *       send ACK to tap
 *     - set @last_ts_sock
 *     - on @seq_ack_to_tap < @seq_from_tap, mark socket for later ACK in bitmap
 *   - periodically:
 *     - if socket is marked in bitmap, query socket for TCP_INFO, on
 *       tcpi_bytes_acked > @tcpi_acked_last, 
 *       set @tcpi_acked_last to tcpi_bytes_acked, set @seq_ack_to_tap
 *       to (tcpi_bytes_acked + @seq_init_from_tap) % 2^32 and
 *       send ACK to tap
 *     - on @seq_ack_to_tap == @seq_from_tap, unmark socket from bitmap
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
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <time.h>

#include "passt.h"
#include "tap.h"
#include "util.h"

/* Approximately maximum number of open descriptors per process */
#define MAX_CONNS			(256 * 1024)

#define MAX_WS				10
#define MAX_WINDOW			(1 << (16 + (MAX_WS)))
#define MSS_DEFAULT			536
#define WINDOW_DEFAULT			4380

#define SYN_TIMEOUT			240000		/* ms */
#define ACK_TIMEOUT			3000
#define ACT_TIMEOUT			7200000
#define FIN_TIMEOUT			240000
#define LAST_ACK_TIMEOUT		240000

#define SOCK_ACK_INTERVAL		20

/* We need to include <linux/tcp.h> for tcpi_bytes_acked, instead of
 * <netinet/tcp.h>, but that doesn't include a definition for SOL_TCP
 */
#define SOL_TCP				IPPROTO_TCP

static char tcp_in_buf[MAX_WINDOW];

static uint8_t tcp_act_fast[MAX_CONNS / 8] = { 0 };
static uint8_t tcp_act_slow[MAX_CONNS / 8] = { 0 };

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
};

#define FIN		(1 << 0)
#define SYN		(1 << 1)
#define RST		(1 << 2)
#define ACK		(1 << 4)

#define OPT_EOL		0
#define OPT_NOP		1
#define OPT_MSS		2
#define OPT_WS		3
#define OPT_SACKP	4
#define OPT_SACK	5
#define OPT_TS		8

/**
 * struct tcp_conn - Descriptor for a TCP connection
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
 * @last_ts_sock:	Last activity timestamp from socket for timeout purposes
 * @last_ts_tap:	Last activity timestamp from tap for timeout purposes
 * @mss_guest:		Maximum segment size advertised by guest
 */
struct tcp_conn {
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

	struct timespec last_ts_sock;
	struct timespec last_ts_tap;

	int mss_guest;
};

static struct tcp_conn tc[MAX_CONNS];

static int tcp_send_to_tap(struct ctx *c, int s, int flags, char *in, int len);

/**
 * tcp_act_fast_set() - Set socket in bitmap for "fast" timeout events
 * @s:		Socket file descriptor number
 */
static void tcp_act_fast_set(int s)
{
	tcp_act_fast[s / 8] |= 1 << (s % 8);
}

/**
 * tcp_act_fast_clear() - Clear socket from bitmap for "fast" timeout events
 * @s:		Socket file descriptor number
 */
static void tcp_act_fast_clear(int s)
{
	tcp_act_fast[s / 8] &= ~(1 << (s % 8));
}

/**
 * tcp_act_slow_set() - Set socket in bitmap for "slow" timeout events
 * @s:		Socket file descriptor number
 */
static void tcp_act_slow_set(int s)
{
	tcp_act_slow[s / 8] |= 1 << (s % 8);
}

/**
 * tcp_act_slow_clear() - Clear socket from bitmap for "slow" timeout events
 * @s:		Socket file descriptor number
 */
static void tcp_act_slow_clear(int s)
{
	tcp_act_slow[s / 8] &= ~(1 << (s % 8));
}

/**
 * tcp_opt_get() - Get option, and value if any, from TCP header
 * @th:		Pointer to TCP header
 * @len:	Length of buffer, including TCP header
 * @type:	Option type to look for
 * @optlen:	Optional, filled with option length if passed
 * @value:	Optional, set to start of option value if passed
 *
 * Return: Option value, meaningful for up to 4 bytes, -1 if not found
 */
static int tcp_opt_get(struct tcphdr *th, unsigned int len, uint8_t type,
		       uint8_t *optlen, void *value)
{
	uint8_t *p, __type, __optlen;

	len -= sizeof(*th);
	p = (uint8_t *)(th + 1);

	if (len > th->doff * 4 - sizeof(*th))
		len = th->doff * 4 - sizeof(*th);

	while (len >= 2) {
		switch (*p) {
		case OPT_EOL:
			return -1;
		case OPT_NOP:
			p++;
			len--;
			break;
		default:
			__type = *(p++);
			__optlen = *(p++);
			len -= 2;

			if (type == __type) {
				if (optlen)
					*optlen = __optlen;
				if (value)
					value = p;

				if (__optlen - 2 == 0)
					return 0;

				if (__optlen - 2 == 1)
					return *p;

				if (__optlen - 2 == 2)
					return ntohs(*(uint16_t *)p);

				return ntohl(*(uint32_t *)p);
			}

			p += __optlen - 2;
			len -= __optlen - 2;
		}
	}

	return -1;
}

/**
 * tcp_close_and_epoll_del() - Close socket and remove from epoll descriptor
 * @c:		Execution context
 * @s:		File descriptor number for socket
 */
static void tcp_close_and_epoll_del(struct ctx *c, int s)
{
	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, s, NULL);
	close(s);
	tcp_act_fast_clear(s);
	tcp_act_slow_clear(s);
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
	tc[s].s = CLOSED;
}

/**
 * tcp_send_to_tap() - Send segment to tap, with options and values from socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @flags:	TCP flags to set
 * @in:		Input buffer, L4 header
 * @len:	Buffer length, at L4
 *
 * Return: -1 on error with connection reset, 0 otherwise
 */
static int tcp_send_to_tap(struct ctx *c, int s, int flags, char *in, int len)
{
	char buf[USHRT_MAX] = { 0 }, *data;
	struct tcp_info info = { 0 };
	socklen_t sl = sizeof(info);
	int ws = 0, have_info = 1;
	struct tcphdr *th;

	if (getsockopt(s, SOL_TCP, TCP_INFO, &info, &sl)) {
		if (!(flags & RST)) {
			tcp_rst(c, s);
			return -1;
		}

		have_info = 0;
	}

	th = (struct tcphdr *)buf;
	data = (char *)(th + 1);

	if (flags & SYN && have_info) {
		if (tc[s].ws_allowed)
			ws = info.tcpi_snd_wscale;

		/* Options: MSS, NOP and window scale if allowed (4-8 bytes) */
		*data++ = 2;
		*data++ = 4;
		*(uint16_t *)data = htons(info.tcpi_snd_mss);
		data += 2;

		if (ws) {
			*data++ = 1;

			*data++ = 3;
			*data++ = 3;
			*data++ = ws;

			th->doff = (20 + 8) / 4;
		} else {
			th->doff = (20 + 4) / 4;
		}

		th->seq = htonl(tc[s].seq_to_tap++);
	} else {
		th->doff = 20 / 4;

		th->seq = htonl(tc[s].seq_to_tap);
		tc[s].seq_to_tap += len;
	}

	if ((info.tcpi_bytes_acked > tc[s].tcpi_acked_last || (flags & ACK) ||
	     len) &&
	    have_info) {
		uint64_t ack_seq;

		th->ack = 1;
		/* info.tcpi_bytes_acked already includes one byte for SYN, but
		 * not for incoming connections.
		 */
		ack_seq = info.tcpi_bytes_acked + tc[s].seq_init_from_tap;
		if (!info.tcpi_bytes_acked)
			ack_seq++;
		ack_seq &= (uint32_t)~0U;

		tc[s].seq_ack_to_tap = ack_seq;
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

	if (have_info)
		th->window = htons(info.tcpi_snd_wnd >> info.tcpi_snd_wscale);
	else
		th->window = WINDOW_DEFAULT;

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
 */
static void tcp_clamp_window(int s, struct tcphdr *th, int len)
{
	int ws;

	if (!tc[s].tap_window) {
		ws = tcp_opt_get(th, len, OPT_WS, NULL, NULL);
		if (ws >= 0 && ws <= MAX_WS) {
			tc[s].ws_allowed = 1;
			tc[s].ws = ws;
		} else {
			tc[s].ws_allowed = 0;
			tc[s].ws = 0;
		}

		/* First value is not scaled. Also, don't clamp yet, to avoid
		 * getting a zero scale just because we set a small window now.
		 */
		tc[s].tap_window = ntohs(th->window);
	} else {
		tc[s].tap_window = ntohs(th->window) << tc[s].ws;
		setsockopt(s, SOL_TCP, TCP_WINDOW_CLAMP,
			   &tc[s].tap_window, sizeof(tc[s].tap_window));
	}
}

/**
 * tcp_conn_from_tap() - Handle connection request (SYN segment) from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Remote address, pointer to sin_addr or sin6_addr
 * @th:		TCP header from tap
 * @len:	Packet length at L4
 */
static void tcp_conn_from_tap(struct ctx *c, int af, void *addr,
			      struct tcphdr *th, size_t len)
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

	tc[s].mss_guest = tcp_opt_get(th, len, OPT_MSS, NULL, NULL);
	if (tc[s].mss_guest < 0)
		tc[s].mss_guest = MSS_DEFAULT;
	sl = sizeof(tc[s].mss_guest);
	setsockopt(s, SOL_TCP, TCP_MAXSEG, &tc[s].mss_guest, sl);

	tcp_clamp_window(s, th, len);

	if (af == AF_INET) {
		sa = (const struct sockaddr *)&addr4;
		sl = sizeof(addr4);

		memset(&tc[s].a.a4.zero, 0, sizeof(tc[s].a.a4.zero));
		memset(&tc[s].a.a4.one, 0xff, sizeof(tc[s].a.a4.one));
		memcpy(&tc[s].a.a4.a, addr, sizeof(tc[s].a.a4.a));
	} else {
		sa = (const struct sockaddr *)&addr6;
		sl = sizeof(addr6);

		memcpy(&tc[s].a.a6, addr, sizeof(tc[s].a.a6));
	}

	tc[s].sock_port = th->dest;
	tc[s].tap_port = th->source;

	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
	ev.data.fd = s;

	tc[s].seq_init_from_tap = ntohl(th->seq);
	tc[s].seq_from_tap = tc[s].seq_init_from_tap + 1;
	tc[s].seq_ack_to_tap = tc[s].seq_from_tap;

	/* TODO: RFC 6528 with SipHash, worth it? */
	tc[s].seq_ack_from_tap = tc[s].seq_to_tap = 0;

	if (connect(s, sa, sl)) {
		if (errno != EINPROGRESS) {
			tcp_rst(c, s);
			return;
		}

		ev.events |= EPOLLOUT;
		tc[s].s = TAP_SYN_SENT;
	} else {
		if (tcp_send_to_tap(c, s, SYN | ACK, NULL, 0))
			return;

		tc[s].s = TAP_SYN_RCVD;
	}

	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, s, &ev);

	return;
}

/**
 * tcp_sock_lookup() - Look up socket given remote address and pair of ports
 * @af:		Address family, AF_INET or AF_INET6
 * @tap_port:	tap-facing port
 * @sock_port:	Socket-facing port
 *
 * Return: file descriptor number for socket, if found, -1 otherwise
 */
static int tcp_sock_lookup(int af, void *addr,
			   in_port_t tap_port, in_port_t sock_port)
{
	int i;

	/* TODO: hash table and lookup. This is just a dummy implementation. */
	for (i = 0; i < MAX_CONNS; i++) {
		if (af == AF_INET && IN6_IS_ADDR_V4MAPPED(&tc[i].a.a6)	&&
		    !memcmp(&tc[i].a.a4.a, addr, sizeof(tc[i].a.a4.a))	&&
		    tc[i].tap_port == tap_port				&&
		    tc[i].sock_port == sock_port			&&
		    tc[i].s)
			return i;

		if (af == AF_INET6					&&
		    !memcmp(&tc[i].a.a6, addr, sizeof(tc[i].a.a6))	&&
		    tc[i].tap_port == tap_port				&&
		    tc[i].sock_port == sock_port			&&
		    tc[i].s)
			return i;
	}

	return -1;
}

/**
 * tcp_conn_from_sock() - Handle new connection request from listening socket
 * @c:		Execution context
 * @fd:		File descriptor number for listening socket
 */
static void tcp_conn_from_sock(struct ctx *c, int fd)
{
	struct sockaddr_storage sa_r, sa_l;
	socklen_t sa_len = sizeof(sa_r);
	struct epoll_event ev = { 0 };
	struct sockaddr_in6 *sa6;
	struct sockaddr_in *sa4;
	int s;

	if (getsockname(fd, (struct sockaddr *)&sa_l, &sa_len))
		return;

	s = accept4(fd, (struct sockaddr *)&sa_r, &sa_len, SOCK_NONBLOCK);
	if (s == -1)
		return;

	if (sa_l.ss_family == AF_INET) {
		sa4 = (struct sockaddr_in *)&sa_r;

		memset(&tc[s].a.a4.zero, 0, sizeof(tc[s].a.a4.zero));
		memset(&tc[s].a.a4.one, 0xff, sizeof(tc[s].a.a4.one));
		memcpy(&tc[s].a.a4.a, &sa4->sin_addr, sizeof(tc[s].a.a4.a));

		tc[s].sock_port = sa4->sin_port;

		sa4 = (struct sockaddr_in *)&sa_l;
		tc[s].tap_port = sa4->sin_port;

	} else if (sa_l.ss_family == AF_INET6) {
		sa6 = (struct sockaddr_in6 *)&sa_r;

		memcpy(&tc[s].a.a6, &sa6->sin6_addr, sizeof(tc[s].a.a6));

		tc[s].sock_port = sa6->sin6_port;

		sa6 = (struct sockaddr_in6 *)&sa_l;
		tc[s].tap_port = sa6->sin6_port;
	}

	/* TODO: RFC 6528 with SipHash, worth it? */
	tc[s].seq_to_tap = 0;

	tc[s].ws_allowed = 1;

	clock_gettime(CLOCK_MONOTONIC, &tc[s].last_ts_sock);
	clock_gettime(CLOCK_MONOTONIC, &tc[s].last_ts_tap);

	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
	ev.data.fd = s;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, s, &ev);

	tc[s].s = SOCK_SYN_SENT;
	tcp_send_to_tap(c, s, SYN, NULL, 0);
}

/**
 * tcp_send_to_sock() - Send buffer to socket, update timestamp and sequence
 * @c:			Execution context
 * @s:			File descriptor number for socket
 * @seq:		Previous TCP sequence, host order
 * @data:		Data buffer
 * @len:		Length at L4
 * @extra_flags:	Additional flags for send(), if any
 *
 * Return: -1 on socket error with connection reset, 0 otherwise
 */
static int tcp_send_to_sock(struct ctx *c, int s, int seq, char *data, int len,
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

		tcp_rst(c, s);
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &tc[s].last_ts_sock);
	tc[s].seq_from_tap = seq + len;

	return 0;
}

/**
 * tcp_check_dupack() - Check if given ACK number is duplicated, update counter
 * @s:		File descriptor number for socket
 * @ack_seq:	ACK sequence, host order
 *
 * Return: 1 on two duplicated ACKs observed, with counter reset, 0 otherwise
 */
static int tcp_check_dupack(int s, uint32_t ack_seq)
{
	if (ack_seq == tc[s].seq_ack_from_tap && ++tc[s].dup_acks == 2) {
		tc[s].dup_acks = 0;
		return 1;
	}

	return 0;
}

/**
 * tcp_sock_consume() - Consume (discard) data from socket buffer
 * @s:		File descriptor number for socket
 * @ack_seq:	ACK sequence, host order
 *
 * Return: -1 on invalid sequence, 0 otherwise
 */
static int tcp_sock_consume(int s, uint32_t ack_seq)
{
	int to_ack;

	/* Implicitly take care of wrap-arounds */
	to_ack = ack_seq - tc[s].seq_ack_from_tap;

	if (to_ack < 0)
		return -1;

	recv(s, NULL, to_ack, MSG_DONTWAIT | MSG_TRUNC);
	tc[s].seq_ack_from_tap = ack_seq;

	return 0;
}

/**
 * tcp_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @s:		File descriptor number for socket
 *
 * Return: non-zero on socket error or pending data, 0 otherwise
 */
static int tcp_data_from_sock(struct ctx *c, int s)
{
	int len, offset, left, send;

	/* Don't dequeue until acknowledged by guest */
	len = recv(s, tcp_in_buf, sizeof(tcp_in_buf), MSG_DONTWAIT | MSG_PEEK);
	if (len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			tcp_rst(c, s);
		return 1;
	}

	if (len == 0) {
		if (tc[s].s >= ESTABLISHED_SOCK_FIN)
			return 0;

		tc[s].s = ESTABLISHED_SOCK_FIN;
		if (tcp_send_to_tap(c, s, FIN | ACK, NULL, 0))
			return 0;

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

		if (tcp_send_to_tap(c, s, 0, tcp_in_buf + offset, send))
			return 0;

		offset += send;
		left -= send;
	}

out:
	clock_gettime(CLOCK_MONOTONIC, &tc[s].last_ts_tap);
	tcp_act_slow_set(s);

	return !!left;
}

/**
 * tcp_tap_handler() - Handle packets from tap and state transitions
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @in:		Input buffer
 * @len:	Length, including TCP header
 */
void tcp_tap_handler(struct ctx *c, int af, void *addr, char *in, size_t len)
{
	struct tcphdr *th = (struct tcphdr *)in;
	size_t off;
	int s, ws;

	if (len < sizeof(*th))
		return;

	off = th->doff * 4;
	if (off < sizeof(*th) || off > len)
		return;

	s = tcp_sock_lookup(af, addr, th->source, th->dest);

	if (s < 0) {
		if (th->syn)
			tcp_conn_from_tap(c, af, addr, th, len);
		return;
	}

	if (th->rst) {
		tcp_close_and_epoll_del(c, s);
		return;
	}

	tcp_clamp_window(s, th, len);

	if (th->ack)
		clock_gettime(CLOCK_MONOTONIC, &tc[s].last_ts_tap);

	switch (tc[s].s) {
	case SOCK_SYN_SENT:
		if (!th->syn || !th->ack)
			return;

		tc[s].mss_guest = tcp_opt_get(th, len, OPT_MSS, NULL, NULL);
		if (tc[s].mss_guest < 0)
			tc[s].mss_guest = MSS_DEFAULT;

		ws = tcp_opt_get(th, len, OPT_WS, NULL, NULL);
		if (ws > MAX_WS) {
			if (tcp_send_to_tap(c, s, RST, NULL, 0))
				return;

			tc[s].seq_to_tap = 0;
			tc[s].ws_allowed = 0;
			tcp_send_to_tap(c, s, SYN, NULL, 0);
			return;
		}

		tc[s].seq_from_tap = tc[s].seq_init_from_tap = ntohl(th->seq);
		tc[s].seq_ack_to_tap = tc[s].seq_from_tap;

		tc[s].s = ESTABLISHED;
		tcp_send_to_tap(c, s, ACK, NULL, 0);
		break;
	case TAP_SYN_SENT:
		break;
	case TAP_SYN_RCVD:
		if (th->fin) {
			shutdown(s, SHUT_WR);
			tc[s].s = FIN_WAIT_1;

			break;
		}

		if (!th->ack) {
			tcp_rst(c, s);
			return;
		}

		tc[s].seq_ack_from_tap = ntohl(th->ack_seq);

		tc[s].s = ESTABLISHED;
		break;
	case ESTABLISHED:
		if (th->ack) {
			int retrans = 0;

			if (len == th->doff)
				retrans = tcp_check_dupack(s, th->ack_seq);

			if (tcp_sock_consume(s, ntohl(th->ack_seq))) {
				tcp_rst(c, s);
				return;
			}

			if (retrans) {
				tc[s].seq_to_tap = tc[s].seq_ack_from_tap;
				tcp_data_from_sock(c, s);
			}
		}

		if (tcp_send_to_sock(c, s, ntohl(th->seq), in + off, len - off,
				     th->psh ? 0 : MSG_MORE))
			break;

		if (th->fin) {
			shutdown(s, SHUT_WR);
			tc[s].s = FIN_WAIT_1;
		}

		break;
	case ESTABLISHED_SOCK_FIN:
		if (tcp_send_to_sock(c, s, ntohl(th->seq), in + off, len - off,
				     th->psh ? 0 : MSG_MORE) < 0)
			break;

		if (th->ack) {
			shutdown(s, SHUT_RD);
			if (!tcp_data_from_sock(c, s))
				tc[s].s = CLOSE_WAIT;

			if (tcp_sock_consume(s, ntohl(th->ack_seq))) {
				tcp_rst(c, s);
				return;
			}
		}

		break;

	case CLOSE_WAIT:
		if (tcp_sock_consume(s, ntohl(th->ack_seq))) {
			tcp_rst(c, s);
			return;
		}

		if (th->fin) {
			shutdown(s, SHUT_WR);
			tc[s].s = LAST_ACK;
		}

		break;
	case FIN_WAIT_1:
	case LAST_ACK:
	case CLOSED:	/* ;) */
		break;
	}

	if (tc[s].seq_to_tap > tc[s].seq_ack_from_tap)
		tcp_act_slow_set(s);
	else
		tcp_act_slow_clear(s);

	if (tc[s].seq_from_tap > tc[s].seq_ack_to_tap)
		tcp_act_fast_set(s);
	else
		tcp_act_fast_clear(s);
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

	if (tcp_send_to_tap(c, s, SYN | ACK, NULL, 0) < 0)
		return;

	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
	ev.data.fd = s;
	epoll_ctl(c->epollfd, EPOLL_CTL_MOD, s, &ev);

	tc[s].s = TAP_SYN_RCVD;
}

/**
 * tcp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @events:	epoll events bitmap
 */
void tcp_sock_handler(struct ctx *c, int s, uint32_t events)
{
	socklen_t sl;
	int so;

	if (tc[s].s == LAST_ACK) {
		tcp_close_and_epoll_del(c, s);
		return;
	}

	sl = sizeof(so);
	if ((events & EPOLLERR) ||
	    getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, &so, &sl)) {
		if (tc[s].s != CLOSED)
			tcp_rst(c, s);
		return;
	}

	if (so) {
		tcp_conn_from_sock(c, s);
		return;
	}

	if (events & EPOLLOUT) {	/* Implies TAP_SYN_SENT */
		tcp_connect_finish(c, s);
		return;
	}

	if (tc[s].s == ESTABLISHED)
		tcp_data_from_sock(c, s);

	if (events & EPOLLRDHUP || events & EPOLLHUP) {
		if (tc[s].s == ESTABLISHED)
			tc[s].s = ESTABLISHED_SOCK_FIN;

		tcp_send_to_tap(c, s, FIN | ACK, NULL, 0);

		if (tc[s].s == FIN_WAIT_1) {
			shutdown(s, SHUT_RD);

			if (tcp_sock_consume(s, ntohl(tc[s].seq_ack_from_tap))) {
				tcp_rst(c, s);
				return;
			}

			tcp_close_and_epoll_del(c, s);
			tc[s].s = CLOSED;
		}
	}
}

/**
 * tcp_sock_init() - Create and bind listening sockets for inbound connections
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int tcp_sock_init(struct ctx *c)
{
	in_port_t port;

	for (port = 0; port < (1 << 15) + (1 << 14); port++) {
		if (c->v4 && sock_l4_add(c, 4, IPPROTO_TCP, htons(port)) < 0)
			return -1;
		if (c->v6 && sock_l4_add(c, 6, IPPROTO_TCP, htons(port)) < 0)
			return -1;
	}

	return 0;
}

/**
 * tcp_periodic_fast_one() - Handler for "fast" timeout events on one socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @ts:		Timestamp from caller
 *
 * Return: 0 if socket needs to be monitored further, non-zero otherwise
 */
int tcp_periodic_fast_one(struct ctx *c, int s, struct timespec *ts)
{
	if (timespec_diff_ms(ts, &tc[s].last_ts_sock) < SOCK_ACK_INTERVAL)
		return 0;

	tc[s].last_ts_sock = *ts;

	tcp_send_to_tap(c, s, 0, NULL, 0);

	return tc[s].seq_from_tap == tc[s].seq_ack_to_tap;
}

/**
 * tcp_periodic_fast() - Handle sockets in "fast" event bitmap, clear as needed
 * @c:		Execution context
 */
void tcp_periodic_fast(struct ctx *c)
{
	long *word = (long *)tcp_act_fast, tmp;
	struct timespec now;
	unsigned int i;
	int n, s;

	clock_gettime(CLOCK_MONOTONIC, &now);

	for (i = 0; i < sizeof(tcp_act_fast) / sizeof(long); i++, word++) {
		tmp = *word;
		while ((n = ffsl(tmp))) {
			tmp &= ~(1UL << (n - 1));

			s = i * sizeof(long) * 8 + n - 1;

			if (tcp_periodic_fast_one(c, s, &now))
				*word &= ~(1UL << (n - 1));
		}
	}
}

/**
 * tcp_periodic_fast_one() - Handler for "slow" timeout events on one socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @ts:		Timestamp from caller
 */
void tcp_periodic_slow_one(struct ctx *c, int s, struct timespec *ts)
{
	switch (tc[s].s) {
	case SOCK_SYN_SENT:
	case TAP_SYN_SENT:
	case TAP_SYN_RCVD:
		if (timespec_diff_ms(ts, &tc[s].last_ts_tap) > SYN_TIMEOUT)
			tcp_rst(c, s);
		break;
	case ESTABLISHED_SOCK_FIN:
		if (timespec_diff_ms(ts, &tc[s].last_ts_tap) > FIN_TIMEOUT) {
			tcp_rst(c, s);
			break;
		}
		/* Falls through */
	case ESTABLISHED:
		if (tc[s].seq_ack_from_tap < tc[s].seq_to_tap &&
		    timespec_diff_ms(ts, &tc[s].last_ts_tap) > ACK_TIMEOUT) {
			tc[s].seq_to_tap = tc[s].seq_ack_from_tap;
			tcp_data_from_sock(c, s);
		}

		if (timespec_diff_ms(ts, &tc[s].last_ts_tap) > ACT_TIMEOUT &&
		    timespec_diff_ms(ts, &tc[s].last_ts_sock) > ACT_TIMEOUT)
			tcp_rst(c, s);

		break;
	case CLOSE_WAIT:
	case FIN_WAIT_1:
		if (timespec_diff_ms(ts, &tc[s].last_ts_tap) > FIN_TIMEOUT)
			tcp_rst(c, s);
		break;
	case LAST_ACK:
		if (timespec_diff_ms(ts, &tc[s].last_ts_sock) >
		    LAST_ACK_TIMEOUT)
			tcp_rst(c, s);
		break;
	case CLOSED:
		break;
	}
}

/**
 * tcp_periodic_slow() - Handle sockets in "slow" event bitmap
 * @c:		Execution context
 */
void tcp_periodic_slow(struct ctx *c)
{
	long *word = (long *)tcp_act_slow, tmp;
	struct timespec now;
	unsigned int i;
	int n;

	clock_gettime(CLOCK_MONOTONIC, &now);

	for (i = 0; i < sizeof(tcp_act_slow) / sizeof(long); i++, word++) {
		tmp = *word;
		while ((n = ffsl(tmp))) {
			tmp &= ~(1UL << (n - 1));
			tcp_periodic_slow_one(c, i * sizeof(long) * 8 + n - 1,
					      &now);
		}
	}
}

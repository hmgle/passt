/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * TCP connection tracking data structures, used by tcp.c and
 * tcp_splice.c.  Shouldn't be included in non-TCP code.
 */
#ifndef TCP_CONN_H
#define TCP_CONN_H

/**
 * struct tcp_conn_common - Common fields for spliced and non-spliced
 * @spliced:		Is this a spliced connection?
 * @in_epoll:		Is the connection in the epoll set?
 */
struct tcp_conn_common {
	bool spliced	:1;
	bool in_epoll	:1;
};

extern const char *tcp_common_flag_str[];

/**
 * struct tcp_tap_conn - Descriptor for a TCP connection (not spliced)
 * @c:			Fields common with tcp_splice_conn
 * @next_index:		Connection index of next item in hash chain, -1 for none
 * @tap_mss:		MSS advertised by tap/guest, rounded to 2 ^ TCP_MSS_BITS
 * @sock:		Socket descriptor number
 * @events:		Connection events, implying connection states
 * @timer:		timerfd descriptor for timeout events
 * @flags:		Connection flags representing internal attributes
 * @retrans:		Number of retransmissions occurred due to ACK_TIMEOUT
 * @ws_from_tap:	Window scaling factor advertised from tap/guest
 * @ws_to_tap:		Window scaling factor advertised to tap/guest
 * @sndbuf:		Sending buffer in kernel, rounded to 2 ^ SNDBUF_BITS
 * @seq_dup_ack_approx:	Last duplicate ACK number sent to tap
 * @addr:		Remote address (IPv4 or IPv6)
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
struct tcp_tap_conn {
	/* Must be first element to match tcp_splice_conn */
	struct tcp_conn_common c;

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
#define ACTIVE_CLOSE		BIT(3)
#define ACK_TO_TAP_DUE		BIT(4)
#define ACK_FROM_TAP_DUE	BIT(5)


#define TCP_MSS_BITS			14
	unsigned int	tap_mss		:TCP_MSS_BITS;
#define MSS_SET(conn, mss)	(conn->tap_mss = (mss >> (16 - TCP_MSS_BITS)))
#define MSS_GET(conn)		(conn->tap_mss << (16 - TCP_MSS_BITS))


#define SNDBUF_BITS		24
	unsigned int	sndbuf		:SNDBUF_BITS;
#define SNDBUF_SET(conn, bytes)	(conn->sndbuf = ((bytes) >> (32 - SNDBUF_BITS)))
#define SNDBUF_GET(conn)	(conn->sndbuf << (32 - SNDBUF_BITS))

	uint8_t		seq_dup_ack_approx;


	union inany_addr addr;
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

/**
 * struct tcp_splice_conn - Descriptor for a spliced TCP connection
 * @c:			Fields common with tcp_tap_conn
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
	/* Must be first element to match tcp_tap_conn */
	struct tcp_conn_common c;

	int a;
	int pipe_a_b[2];
	int b;
	int pipe_b_a[2];

	uint8_t events;
#define SPLICE_CLOSED			0
#define SPLICE_CONNECT			BIT(0)
#define SPLICE_ESTABLISHED		BIT(1)
#define A_OUT_WAIT			BIT(2)
#define B_OUT_WAIT			BIT(3)
#define A_FIN_RCVD			BIT(4)
#define B_FIN_RCVD			BIT(5)
#define A_FIN_SENT			BIT(6)
#define B_FIN_SENT			BIT(7)

	uint8_t flags;
#define SPLICE_V6			BIT(0)
#define RCVLOWAT_SET_A			BIT(1)
#define RCVLOWAT_SET_B			BIT(2)
#define RCVLOWAT_ACT_A			BIT(3)
#define RCVLOWAT_ACT_B			BIT(4)
#define CLOSING				BIT(5)

	uint32_t a_read;
	uint32_t a_written;
	uint32_t b_read;
	uint32_t b_written;
};

/**
 * union tcp_conn - Descriptor for a TCP connection (spliced or non-spliced)
 * @c:			Fields common between all variants
 * @tap:		Fields specific to non-spliced connections
 * @splice:		Fields specific to spliced connections
*/
union tcp_conn {
	struct tcp_conn_common c;
	struct tcp_tap_conn tap;
	struct tcp_splice_conn splice;
};

/* TCP connections */
extern union tcp_conn tc[];

/* Socket pools */
#define TCP_SOCK_POOL_SIZE		32

extern int init_sock_pool4	[TCP_SOCK_POOL_SIZE];
extern int init_sock_pool6	[TCP_SOCK_POOL_SIZE];

void tcp_splice_conn_update(struct ctx *c, struct tcp_splice_conn *new);
void tcp_table_compact(struct ctx *c, union tcp_conn *hole);
void tcp_splice_destroy(struct ctx *c, union tcp_conn *conn_union);
void tcp_splice_timer(struct ctx *c, union tcp_conn *conn_union);
void tcp_sock_refill_pool(const struct ctx *c, int pool[], int af);
void tcp_splice_refill(const struct ctx *c);

#endif /* TCP_CONN_H */

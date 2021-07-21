#ifndef TCP_H
#define TCP_H

#define TCP_TIMER_INTERVAL		20 /* ms */

#define TCP_MAX_CONNS			(128 * 1024)
#define TCP_MAX_SOCKS			(TCP_MAX_CONNS + USHRT_MAX * 2)

struct ctx;

void tcp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      struct timespec *now);
int tcp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count, struct timespec *now);
int tcp_sock_init(struct ctx *c);
void tcp_timer(struct ctx *c, struct timespec *ts);

/**
 * union tcp_epoll_ref - epoll reference portion for TCP connections
 * @listen:		Set if this file descriptor is a listening socket
 * @splice:		Set if descriptor is associated to a spliced connection
 * @v6:			Set for IPv6 sockets or connections
 * @index:		Index of connection in table, or port for bound sockets
 * @u32:		Opaque u32 value of reference
 */
union tcp_epoll_ref {
	struct {
		uint32_t	listen:1,
				splice:1,
				v6:1,
				index:20;
	};
	uint32_t u32;
};

/**
 * struct tcp_ctx - Execution context for TCP routines
 * @hash_secret:	128-bit secret for hash functions, ISN and hash table
 * @tap_conn_count:	Count of tap connections in connection table
 * @splice_conn_count:	Count of spliced connections in connection table
 * @port4_to_tap:	IPv4 ports bound host/init-side, packets to guest/tap
 * @port6_to_tap:	IPv6 ports bound host/init-side, packets to guest/tap
 * @port4_to_init:	IPv4 ports bound namespace-side, spliced to init
 * @port6_to_init:	IPv6 ports bound namespace-side, spliced to init
 * @port4_to_ns:	IPv4 ports bound init-side, spliced to namespace
 * @port6_to_ns:	IPv6 ports bound init-side, spliced to namespace
 * @timer_run:		Timestamp of most recent timer run
 */
struct tcp_ctx {
	uint64_t hash_secret[2];
	int tap_conn_count;
	int splice_conn_count;
	uint8_t port4_to_tap	[USHRT_MAX / 8];
	uint8_t port6_to_tap	[USHRT_MAX / 8];
	uint8_t port4_to_init	[USHRT_MAX / 8];
	uint8_t port6_to_init	[USHRT_MAX / 8];
	uint8_t port4_to_ns	[USHRT_MAX / 8];
	uint8_t port6_to_ns	[USHRT_MAX / 8];
	struct timespec timer_run;
};

#endif /* TCP_H */

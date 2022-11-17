/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_H
#define TCP_H

#define TCP_TIMER_INTERVAL		1000	/* ms */

#define TCP_CONN_INDEX_BITS		17	/* 128k */
#define TCP_MAX_CONNS			(1 << TCP_CONN_INDEX_BITS)

#define TCP_SOCK_POOL_SIZE		32

struct ctx;

void tcp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      const struct timespec *now);
int tcp_tap_handler(struct ctx *c, int af, const void *addr,
		    const struct pool *p, const struct timespec *now);
void tcp_sock_init(const struct ctx *c, sa_family_t af, const void *addr,
		   const char *ifname, in_port_t port);
int tcp_init(struct ctx *c);
void tcp_timer(struct ctx *c, const struct timespec *ts);
void tcp_defer_handler(struct ctx *c);

void tcp_sock_set_bufsize(const struct ctx *c, int s);
void tcp_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s,
		       const struct in_addr *ip_da);

/**
 * union tcp_epoll_ref - epoll reference portion for TCP connections
 * @listen:		Set if this file descriptor is a listening socket
 * @outbound:		Listening socket maps to outbound, spliced connection
 * @v6:			Set for IPv6 sockets or connections
 * @timer:		Reference is a timerfd descriptor for connection
 * @index:		Index of connection in table, or port for bound sockets
 * @u32:		Opaque u32 value of reference
 */
union tcp_epoll_ref {
	struct {
		uint32_t	listen:1,
				outbound:1,
				v6:1,
				timer:1,
				index:20;
	} tcp;
	uint32_t u32;
};

/**
 * struct tcp_ctx - Execution context for TCP routines
 * @hash_secret:	128-bit secret for hash functions, ISN and hash table
 * @conn_count:		Count of total connections in connection table
 * @splice_conn_count:	Count of spliced connections in connection table
 * @port_to_tap:	Ports bound host-side, packets to tap or spliced
 * @fwd_in:		Port forwarding configuration for inbound packets
 * @fwd_out:		Port forwarding configuration for outbound packets
 * @timer_run:		Timestamp of most recent timer run
 * @kernel_snd_wnd:	Kernel reports sending window (with commit 8f7baad7f035)
 * @pipe_size:		Size of pipes for spliced connections
 */
struct tcp_ctx {
	uint64_t hash_secret[2];
	int conn_count;
	int splice_conn_count;
	struct port_fwd fwd_in;
	struct port_fwd fwd_out;
	struct timespec timer_run;
#ifdef HAS_SND_WND
	int kernel_snd_wnd;
#endif
	size_t pipe_size;
};

#endif /* TCP_H */

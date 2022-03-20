/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_H
#define TCP_H

#define REFILL_INTERVAL			1000	/* ms */
#define PORT_DETECT_INTERVAL		1000
#define TCP_TIMER_INTERVAL	MIN(REFILL_INTERVAL, PORT_DETECT_INTERVAL)

#define TCP_CONN_INDEX_BITS		17	/* 128k */
#define TCP_MAX_CONNS			(1 << TCP_CONN_INDEX_BITS)
#define TCP_MAX_SOCKS			(TCP_MAX_CONNS + USHRT_MAX * 2)

#define TCP_SOCK_POOL_SIZE		32

struct ctx;

void tcp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      struct timespec *now);
int tcp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_l4_msg *msg, int count, struct timespec *now);
int tcp_sock_init(struct ctx *c, struct timespec *now);
void tcp_timer(struct ctx *c, struct timespec *now);
void tcp_defer_handler(struct ctx *c);

void tcp_sock_set_bufsize(struct ctx *c, int s);
void tcp_update_l2_buf(unsigned char *eth_d, unsigned char *eth_s,
		       const uint32_t *ip_da);
void tcp_remap_to_tap(in_port_t port, in_port_t delta);
void tcp_remap_to_init(in_port_t port, in_port_t delta);

/**
 * union tcp_epoll_ref - epoll reference portion for TCP connections
 * @listen:		Set if this file descriptor is a listening socket
 * @splice:		Set if descriptor is associated to a spliced connection
 * @v6:			Set for IPv6 sockets or connections
 * @timer:		Reference is a timerfd descriptor for connection
 * @index:		Index of connection in table, or port for bound sockets
 * @u32:		Opaque u32 value of reference
 */
union tcp_epoll_ref {
	struct {
		uint32_t	listen:1,
				splice:1,
				v6:1,
				timer:1,
				index:20;
	} tcp;
	uint32_t u32;
};

/**
 * struct tcp_ctx - Execution context for TCP routines
 * @hash_secret:	128-bit secret for hash functions, ISN and hash table
 * @conn_count:		Count of connections (not spliced) in connection table
 * @splice_conn_count:	Count of spliced connections in connection table
 * @port_to_tap:	Ports bound host-side, packets to tap or spliced
 * @init_detect_ports:	If set, periodically detect ports bound in init
 * @port_to_init:	Ports bound namespace-side, spliced to init
 * @ns_detect_ports:	If set, periodically detect ports bound in namespace
 * @timer_run:		Timestamp of most recent timer run
 * @kernel_snd_wnd:	Kernel reports sending window (with commit 8f7baad7f035)
 * @pipe_size:		Size of pipes for spliced connections
 * @refill_ts:		Time of last refill operation for pools of sockets/pipes
 * @port_detect_ts:	Time of last TCP port detection/rebind, if enabled
 */
struct tcp_ctx {
	uint64_t hash_secret[2];
	int conn_count;
	int splice_conn_count;
	uint8_t port_to_tap	[USHRT_MAX / 8];
	int init_detect_ports;
	uint8_t port_to_init	[USHRT_MAX / 8];
	int ns_detect_ports;
	struct timespec timer_run;
#ifdef HAS_SND_WND
	int kernel_snd_wnd;
#endif
	size_t pipe_size;
	struct timespec refill_ts;
	struct timespec port_detect_ts;
};

#endif /* TCP_H */

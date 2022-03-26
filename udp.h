/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UDP_H
#define UDP_H

#define UDP_TIMER_INTERVAL		1000 /* ms */

void udp_sock_handler(const struct ctx *c, union epoll_ref ref, uint32_t events,
		      const struct timespec *now);
int udp_tap_handler(struct ctx *c, int af, const void *addr,
		    const struct pool *p, const struct timespec *now);
int udp_sock_init(const struct ctx *c);
void udp_timer(struct ctx *c, const struct timespec *ts);
void udp_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s,
		       const uint32_t *ip_da);
void udp_remap_to_tap(in_port_t port, in_port_t delta);
void udp_remap_to_init(in_port_t port, in_port_t delta);

/**
 * union udp_epoll_ref - epoll reference portion for TCP connections
 * @bound:		Set if this file descriptor is a bound socket
 * @splice:		Set if descriptor is associated to "spliced" connection
 * @v6:			Set for IPv6 sockets or connections
 * @port:		Source port for connected sockets, bound port otherwise
 * @u32:		Opaque u32 value of reference
 */
union udp_epoll_ref {
	struct {
		uint32_t	bound:1,
				splice:3,
#define UDP_TO_NS		1
#define	UDP_TO_INIT		2
#define UDP_BACK_TO_NS		3
#define UDP_BACK_TO_INIT	4

				v6:1,
				port:16;
	} udp;
	uint32_t u32;
};

/**
 * struct udp_ctx - Execution context for UDP
 * @port_to_tap:	Ports bound host-side, data to tap or ns L4 socket
 * @init_detect_ports:	If set, periodically detect ports bound in init (TODO)
 * @port_to_init:	Ports bound namespace-side, data to init L4 socket
 * @ns_detect_ports:	If set, periodically detect ports bound in namespace
 * @timer_run:		Timestamp of most recent timer run
 */
struct udp_ctx {
	uint8_t port_to_tap		[USHRT_MAX / 8];
	int init_detect_ports;
	uint8_t port_to_init		[USHRT_MAX / 8];
	int ns_detect_ports;
	struct timespec timer_run;
};

#endif /* UDP_H */

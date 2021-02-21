// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *
 * udp.c - UDP L2-L4 translation routines
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 */

/**
 * DOC: Theory of Operation
 *
 *
 * For UDP, no state machine or any particular tracking is required. Try to
 * create and bind sets of 2^16 sockets, one for IPv4 and one for IPv6. Binding
 * will fail on ports that are already bound, or low ports depending on
 * capabilities.
 *
 * Packets are forwarded back and forth, by prepending and stripping UDP headers
 * in the obvious way, with no port translation.
 *
 */

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
#include <linux/udp.h>
#include <time.h>

#include "passt.h"
#include "tap.h"
#include "util.h"

static int udp4_sock_port[USHRT_MAX];
static int udp6_sock_port[USHRT_MAX];

/**
 * udp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @events:	epoll events bitmap
 */
void udp_sock_handler(struct ctx *c, int s, uint32_t events)
{
	struct in6_addr a6 = { .s6_addr = {    0,    0,    0,    0,
					       0,    0,    0,    0,
					       0,    0, 0xff, 0xff,
					       0,    0,    0,    0 } };
	struct sockaddr_storage sr, sl;
	socklen_t slen = sizeof(sr);
	char buf[USHRT_MAX];
	struct udphdr *uh;
	int n;

	(void)events;

	n = recvfrom(s, buf + sizeof(*uh), sizeof(buf) - sizeof(*uh),
		     MSG_DONTWAIT, (struct sockaddr *)&sr, &slen);
	if (n < 0)
		return;

	uh = (struct udphdr *)buf;

	if (getsockname(s, (struct sockaddr *)&sl, &slen))
		return;

	if (sl.ss_family == AF_INET) {
		struct sockaddr_in *sr4 = (struct sockaddr_in *)&sr;
		struct sockaddr_in *sl4 = (struct sockaddr_in *)&sl;

		memcpy(&a6.s6_addr[12], &sr4->sin_addr, sizeof(sr4->sin_addr));
		uh->source = sr4->sin_port;
		uh->dest = sl4->sin_port;
		uh->len = htons(n + sizeof(*uh));

		tap_ip_send(c, &a6, IPPROTO_UDP, buf, n + sizeof(*uh));
	} else if (sl.ss_family == AF_INET6) {
		struct sockaddr_in6 *sr6 = (struct sockaddr_in6 *)&sr;
		struct sockaddr_in6 *sl6 = (struct sockaddr_in6 *)&sl;

		uh->source = sr6->sin6_port;
		uh->dest = sl6->sin6_port;
		uh->len = htons(n + sizeof(*uh));

		tap_ip_send(c, &sr6->sin6_addr, IPPROTO_UDP,
			    buf, n + sizeof(*uh));
	}
}

/**
 * tcp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @in:		Input buffer
 * @len:	Length, including UDP header
 */
void udp_tap_handler(struct ctx *c, int af, void *addr, char *in, size_t len)
{
	struct udphdr *uh = (struct udphdr *)in;
	int s;

	(void)c;

	if (af == AF_INET) {
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_port = uh->dest,
		};

		if (!(s = udp4_sock_port[ntohs(uh->source)]))
			return;

		sa.sin_addr = *(struct in_addr *)addr;

		sendto(s, in + sizeof(*uh), len - sizeof(*uh), MSG_DONTWAIT,
		       (struct sockaddr *)&sa, sizeof(sa));
	} else if (af == AF_INET6) {
		struct sockaddr_in6 sa = {
			.sin6_family = AF_INET6,
			.sin6_port = uh->dest,
			.sin6_addr = *(struct in6_addr *)addr,
		};

		if (!(s = udp6_sock_port[ntohs(uh->source)]))
			return;

		sendto(s, in + sizeof(*uh), len - sizeof(*uh),
		       MSG_DONTWAIT | MSG_NOSIGNAL,
		       (struct sockaddr *)&sa, sizeof(sa));
	}
}

/**
 * udp_sock_init() - Create and bind listening sockets for inbound packets
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int udp_sock_init(struct ctx *c)
{
	in_port_t port;
	int s;

	for (port = 0; port < USHRT_MAX; port++) {
		if (c->v4) {
			if ((s = sock_l4_add(c, 4, IPPROTO_UDP, port)) < 0)
				return -1;

			udp4_sock_port[port] = s;
		}

		if (c->v6) {
			if ((s = sock_l4_add(c, 6, IPPROTO_UDP, port)) < 0)
				return -1;

			udp6_sock_port[port] = s;
		}
	}

	return 0;
}

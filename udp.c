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
#include <sys/uio.h>
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
	ssize_t n;

	if (events == EPOLLERR)
		return;

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

		if (ntohl(sr4->sin_addr.s_addr) == INADDR_LOOPBACK ||
		    ntohl(sr4->sin_addr.s_addr) == INADDR_ANY)
			sr4->sin_addr.s_addr = c->gw4;

		memcpy(&a6.s6_addr[12], &sr4->sin_addr, sizeof(sr4->sin_addr));
		uh->source = sr4->sin_port;
		uh->dest = sl4->sin_port;
		uh->len = htons(n + sizeof(*uh));

		tap_ip_send(c, &a6, IPPROTO_UDP, buf, n + sizeof(*uh));
	} else if (sl.ss_family == AF_INET6) {
		struct sockaddr_in6 *sr6 = (struct sockaddr_in6 *)&sr;
		struct sockaddr_in6 *sl6 = (struct sockaddr_in6 *)&sl;

		if (IN6_IS_ADDR_LOOPBACK(&sr6->sin6_addr))
			memcpy(&sr6->sin6_addr, &c->gw6, sizeof(c->gw6));

		uh->source = sr6->sin6_port;
		uh->dest = sl6->sin6_port;
		uh->len = htons(n + sizeof(*uh));

		tap_ip_send(c, &sr6->sin6_addr, IPPROTO_UDP,
			    buf, n + sizeof(*uh));
	}
}

/**
 * udp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @msg:	Input messages
 * @count:	Message count
 *
 * Return: count of consumed packets
 */
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count)
{
	/* The caller already checks that all the messages have the same source
	 * and destination, so we can just take those from the first message.
	 */
	struct udphdr *uh = (struct udphdr *)msg[0].l4h;
	struct mmsghdr mm[UIO_MAXIOV] = { 0 };
	struct iovec m[UIO_MAXIOV];
	struct sockaddr_in6 s_in6;
	struct sockaddr_in s_in;
	struct sockaddr *sa;
	socklen_t sl;
	int i, s;

	(void)c;

	if (af == AF_INET) {
		s_in = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_port = uh->dest,
			.sin_addr = *(struct in_addr *)addr,
		};

		sa = (struct sockaddr *)&s_in;
		sl = sizeof(s_in);
	} else if (af == AF_INET6) {
		s_in6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = uh->dest,
			.sin6_addr = *(struct in6_addr *)addr,
		};

		sa = (struct sockaddr *)&s_in6;
		sl = sizeof(s_in6);
	} else {
		return count;
	}

	for (i = 0; i < count; i++) {
		m[i].iov_base = (char *)((struct udphdr *)msg[i].l4h + 1);
		m[i].iov_len = msg[i].l4_len - sizeof(*uh);

		mm[i].msg_hdr.msg_name = sa;
		mm[i].msg_hdr.msg_namelen = sl;

		mm[i].msg_hdr.msg_iov = m + i;
		mm[i].msg_hdr.msg_iovlen = 1;
	}

	if (af == AF_INET) {
		if (!(s = udp4_sock_port[ntohs(uh->source)]))
			return count;
	} else if (af == AF_INET6) {
		if (!(s = udp6_sock_port[ntohs(uh->source)]))
			return count;
	} else {
		return count;
	}

	count = sendmmsg(s, mm, count, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (count < 0)
		return 1;

	return count;
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

	c->udp.fd_min = INT_MAX;
	c->udp.fd_max = 0;

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

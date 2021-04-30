// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *
 * icmp.c - ICMP/ICMPv6 echo proxy
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
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
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <time.h>

#include "passt.h"
#include "tap.h"
#include "util.h"
#include "icmp.h"

/**
 * icmp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @events:	epoll events bitmap
 * @pkt_buf:	Buffer to receive packets, currently unused
 * @now:	Current timestamp, unused
 */
void icmp_sock_handler(struct ctx *c, int s, uint32_t events, char *pkt_buf,
		       struct timespec *now)
{
	struct in6_addr a6 = { .s6_addr = {    0,    0,    0,    0,
					       0,    0,    0,    0,
					       0,    0, 0xff, 0xff,
					       0,    0,    0,    0 } };
	struct sockaddr_storage sr, sl;
	socklen_t slen = sizeof(sr);
	char buf[USHRT_MAX];
	ssize_t n;

	(void)events;
	(void)pkt_buf;
	(void)now;

	n = recvfrom(s, buf, sizeof(buf), MSG_DONTWAIT,
		     (struct sockaddr *)&sr, &slen);
	if (n < 0)
		return;

	if (getsockname(s, (struct sockaddr *)&sl, &slen))
		return;

	if (sl.ss_family == AF_INET) {
		struct sockaddr_in *sr4 = (struct sockaddr_in *)&sr;

		memcpy(&a6.s6_addr[12], &sr4->sin_addr, sizeof(sr4->sin_addr));

		tap_ip_send(c, &a6, IPPROTO_ICMP, buf, n);
	} else if (sl.ss_family == AF_INET6) {
		struct sockaddr_in6 *sr6 = (struct sockaddr_in6 *)&sr;

		tap_ip_send(c, &sr6->sin6_addr, IPPROTO_ICMPV6, buf, n);
	}
}

/**
 * icmp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @msg:	Input message
 * @count:	Message count (always 1 for ICMP)
 * @now:	Current timestamp, unused
 *
 * Return: count of consumed packets (always 1, even if malformed)
 */
int icmp_tap_handler(struct ctx *c, int af, void *addr,
		     struct tap_msg *msg, int count, struct timespec *now)
{
	(void)count;
	(void)now;

	if (af == AF_INET) {
		struct icmphdr *ih = (struct icmphdr *)msg[0].l4h;
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_ANY),
		};

		if (msg[0].l4_len < sizeof(*ih) || ih->type != ICMP_ECHO)
			return 1;

		sa.sin_port = ih->un.echo.id;
		bind(c->icmp.s4, (struct sockaddr *)&sa, sizeof(sa));

		sa.sin_addr = *(struct in_addr *)addr;
		sendto(c->icmp.s4, msg[0].l4h, msg[0].l4_len,
		       MSG_DONTWAIT | MSG_NOSIGNAL,
		       (struct sockaddr *)&sa, sizeof(sa));
	} else if (af == AF_INET6) {
		struct sockaddr_in6 sa = {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_ANY_INIT,
		};
		struct icmp6hdr *ih = (struct icmp6hdr *)msg[0].l4h;

		if (msg[0].l4_len < sizeof(*ih) ||
		    (ih->icmp6_type != 128 && ih->icmp6_type != 129))
			return 1;

		sa.sin6_port = ih->icmp6_identifier;
		bind(c->icmp.s6, (struct sockaddr *)&sa, sizeof(sa));

		sa.sin6_addr = *(struct in6_addr *)addr;
		sendto(c->icmp.s6, msg[0].l4h, msg[0].l4_len,
		       MSG_DONTWAIT | MSG_NOSIGNAL,
		       (struct sockaddr *)&sa, sizeof(sa));
	}

	return 1;
}

/**
 * icmp_sock_init() - Create ICMP, ICMPv6 sockets for echo requests and replies
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int icmp_sock_init(struct ctx *c)
{
	c->icmp.fd_min = INT_MAX;
	c->icmp.fd_max = 0;

	if (c->v4 && (c->icmp.s4 = sock_l4(c, AF_INET, IPPROTO_ICMP, 0)) < 0)
		return -1;

	if (c->v6 && (c->icmp.s6 = sock_l4(c, AF_INET6, IPPROTO_ICMPV6, 0)) < 0)
		return -1;

	return 0;
}

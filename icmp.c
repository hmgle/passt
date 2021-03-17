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
 */
void icmp_sock_handler(struct ctx *c, int s, uint32_t events)
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
 * @in:		Input buffer
 * @len:	Length, including UDP header
 */
void icmp_tap_handler(struct ctx *c, int af, void *addr, char *in, size_t len)
{
	if (af == AF_INET) {
		struct icmphdr *ih = (struct icmphdr *)in;
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_ANY),
		};

		if (len < sizeof(*ih) || ih->type != ICMP_ECHO)
			return;

		sa.sin_port = ih->un.echo.id;
		bind(c->icmp.s4, (struct sockaddr *)&sa, sizeof(sa));

		sa.sin_addr = *(struct in_addr *)addr;
		sendto(c->icmp.s4, in, len, MSG_DONTWAIT,
		       (struct sockaddr *)&sa, sizeof(sa));
	} else if (af == AF_INET6) {
		struct sockaddr_in6 sa = {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_ANY_INIT,
		};
		struct icmp6hdr *ih = (struct icmp6hdr *)in;

		if (len < sizeof(*ih) ||
		    (ih->icmp6_type != 128 && ih->icmp6_type != 129))
			return;

		sa.sin6_port = ih->icmp6_identifier;
		bind(c->icmp.s6, (struct sockaddr *)&sa, sizeof(sa));

		sa.sin6_addr = *(struct in6_addr *)addr;
		sendto(c->icmp.s6, in, len, MSG_DONTWAIT | MSG_NOSIGNAL,
		       (struct sockaddr *)&sa, sizeof(sa));
	}
}

/**
 * icmp_sock_init() - Create ICMP, ICMPv6 sockets for echo requests and replies
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int icmp_sock_init(struct ctx *c)
{
	if (c->v4 && (c->icmp.s4 = sock_l4_add(c, 4, IPPROTO_ICMP, 0)) < 0)
		return -1;

	if (c->v6 && (c->icmp.s6 = sock_l4_add(c, 6, IPPROTO_ICMPV6, 0)) < 0)
		return -1;

	return 0;
}

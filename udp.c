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
 * For UDP, a reduced version of port-based connection tracking is implemented
 * with two purposes:
 * - binding ephemeral ports when they're used as source port by the guest, so
 *   that replies on those ports can be forwarded back to the guest, with a
 *   fixed 180s timeout for this binding
 * - packets received from the local host get their source changed to a local
 *   address (gateway address) so that they can be forwarded to the guest, and
 *   packets sent as replies by the guest need their destination address to
 *   be changed back to the address of the local host. This is dynamic to allow
 *   connections from the gateway as well, and uses the same fixed 180s timeout
 * 
 * Sockets for ephemeral and non-ephemeral ports are created and at
 * initialisation time, one set for IPv4 and one for IPv6. Non-ephemeral ports
 * are bound at initialisation time, ephemeral ports are bound dynamically.
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

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */

struct udp_port {
	int s;
	time_t ts_ephemeral;
	time_t ts_local;
};

static struct udp_port up4[USHRT_MAX];
static struct udp_port up6[USHRT_MAX];

/* Bitmaps, activity monitoring needed for port */
static uint8_t udp4_act[USHRT_MAX / 8];
static uint8_t udp6_act[USHRT_MAX / 8];

/**
 * udp_act_set() - Set port in bitmap for timed events
 * @af:		Protocol family
 * @s:		Port number
 */
static void udp_act_set(int af, int p)
{
	if (af == AF_INET)
		udp4_act[p / 8] |= 1 << (p % 8);
	else
		udp6_act[p / 8] |= 1 << (p % 8);
}

/**
 * udp_act_clear() - Clear port from bitmap for timed events
 * @af:		Protocol family
 * @s:		Port number
 */
static void udp_act_clear(int af, int p)
{
	if (af == AF_INET)
		udp4_act[p / 8] &= ~(1 << (p % 8));
	else
		udp6_act[p / 8] &= ~(1 << (p % 8));
}

/**
 * udp_sock_handler_local() - Replace address if local, update timestamp
 * @c:		Execution context
 * @sa:		Socket address as struct sockaddr_in or sockaddr_in6
 * @now:	Current timestamp
 */
static void udp_sock_handler_local(struct ctx *c, int af, void *sa,
				   struct timespec *now)
{
	if (af == AF_INET) {
		struct sockaddr_in *s_in = (struct sockaddr_in *)sa;

		s_in->sin_addr.s_addr = c->gw4;

		up4[ntohs(s_in->sin_port)].ts_local = now->tv_sec;
		udp_act_set(AF_INET, ntohs(s_in->sin_port));
	} else {
		struct sockaddr_in6 *s_in6 = (struct sockaddr_in6 *)sa;

		memcpy(&s_in6->sin6_addr, &c->gw6, sizeof(c->gw6));

		up6[ntohs(s_in6->sin6_port)].ts_local = now->tv_sec;
		udp_act_set(AF_INET6, ntohs(s_in6->sin6_port));
	}
}

/**
 * udp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @s:		File descriptor number for socket
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
void udp_sock_handler(struct ctx *c, int s, uint32_t events,
		      struct timespec *now)
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
			udp_sock_handler_local(c, AF_INET, sr4, now);

		memcpy(&a6.s6_addr[12], &sr4->sin_addr, sizeof(sr4->sin_addr));
		uh->source = sr4->sin_port;
		uh->dest = sl4->sin_port;
		uh->len = htons(n + sizeof(*uh));

		tap_ip_send(c, &a6, IPPROTO_UDP, buf, n + sizeof(*uh));
	} else if (sl.ss_family == AF_INET6) {
		struct sockaddr_in6 *sr6 = (struct sockaddr_in6 *)&sr;
		struct sockaddr_in6 *sl6 = (struct sockaddr_in6 *)&sl;

		if (IN6_IS_ADDR_LOOPBACK(&sr6->sin6_addr))
			udp_sock_handler_local(c, AF_INET6, sr6, now);

		uh->source = sr6->sin6_port;
		uh->dest = sl6->sin6_port;
		uh->len = htons(n + sizeof(*uh));

		tap_ip_send(c, &sr6->sin6_addr, IPPROTO_UDP,
			    buf, n + sizeof(*uh));
	}
}

/**
 * udp_tap_handler_ephemeral() - Bind ephemeral source port, update timestamp
 * @af:		Address family, AF_INET or AF_INET6
 * @src:	Source port, host order
 * @now:	Current timestamp
 */
static void udp_tap_handler_ephemeral(int af, in_port_t src,
				      struct timespec *now)
{
	struct sockaddr *addr = NULL;
	struct sockaddr_in6 s_in6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(src),
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	struct sockaddr_in s_in = {
		.sin_family = AF_INET,
		.sin_port = htons(src),
		.sin_addr = { .s_addr = INADDR_ANY },
	};
	socklen_t sl;
	int s;

	if (af == AF_INET) {
		if (!up4[src].ts_ephemeral) {
			s = up4[src].s;
			addr = (struct sockaddr *)&s_in;
			sl = sizeof(s_in);
		}
	} else {
		if (!up6[src].ts_ephemeral) {
			s = up6[src].s;
			addr = (struct sockaddr *)&s_in6;
			sl = sizeof(s_in6);
		}
	}

	if (addr) {
		if (bind(s, addr, sl))
			return;

		udp_act_set(af, src);
	}

	if (af == AF_INET)
		up4[src].ts_ephemeral = now->tv_sec;
	else
		up6[src].ts_ephemeral = now->tv_sec;
}

/**
 * udp_tap_handler_local() - Set address to local if needed, update timestamp
 * @af:		Address family, AF_INET or AF_INET6
 * @dst:	Destination port, host order
 * @sa:		Socket address as struct sockaddr_in or sockaddr_in6 to modify
 * @now:	Current timestamp
 */
static void udp_tap_handler_local(int af, in_port_t dst, void *sa,
				  struct timespec *now)
{
	if (af == AF_INET) {
		if (up4[dst].ts_local) {
			struct sockaddr_in *s_in = (struct sockaddr_in *)sa;

			s_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			up4[dst].ts_local = now->tv_sec;
		}
	} else {
		if (up6[dst].ts_local) {
			struct sockaddr_in6 *s_in6 = (struct sockaddr_in6 *)sa;

			s_in6->sin6_addr = in6addr_loopback;
			up6[dst].ts_local = now->tv_sec;
		}
	}
}

/**
 * udp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @msg:	Input messages
 * @count:	Message count
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 */
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count, struct timespec *now)
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
	in_port_t src, dst;
	socklen_t sl;
	int i, s;

	(void)c;

	if (msg[0].l4_len < sizeof(*uh))
		return 1;

	src = ntohs(uh->source);
	dst = ntohs(uh->dest);

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
		if (!(s = up4[src].s))
			return count;

		if (s_in.sin_addr.s_addr == c->gw4)
			udp_tap_handler_local(AF_INET, dst, &s_in, now);
	} else {
		if (!(s = up6[src].s))
			return count;

		if (!memcmp(addr, &c->gw6, sizeof(c->gw6)))
			udp_tap_handler_local(AF_INET6, dst, &s_in6, now);
	}

	if (PORT_IS_EPHEMERAL(src))
		udp_tap_handler_ephemeral(af, src, now);

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
			if ((s = sock_l4(c, AF_INET, IPPROTO_UDP, port)) < 0)
				return -1;

			up4[port].s = s;
		}

		if (c->v6) {
			if ((s = sock_l4(c, AF_INET6, IPPROTO_UDP, port)) < 0)
				return -1;

			up6[port].s = s;
		}
	}

	return 0;
}

/**
 * udp_timer_one() - Handler for timed events on one port
 * @af:		Address family, AF_INET or AF_INET6
 * @p:		Port number, host order
 * @ts:		Timestamp from caller
 */
static void udp_timer_one(struct ctx *c, int af, in_port_t p,
			  struct timespec *ts)
{
	int s = -1;

	if (af == AF_INET) {
		if (ts->tv_sec - up4[p].ts_ephemeral > UDP_CONN_TIMEOUT)
			up4[p].ts_ephemeral = 0;
		if (ts->tv_sec - up4[p].ts_local > UDP_CONN_TIMEOUT)
			up4[p].ts_local = 0;

		if (!up4[p].ts_ephemeral && !up4[p].ts_local) {
			udp_act_clear(AF_INET, p);
			s = up4[p].s;
		}
	} else {
		if (ts->tv_sec - up6[p].ts_ephemeral > UDP_CONN_TIMEOUT)
			up6[p].ts_ephemeral = 0;
		if (ts->tv_sec - up6[p].ts_local > UDP_CONN_TIMEOUT)
			up6[p].ts_local = 0;

		if (!up6[p].ts_ephemeral && !up6[p].ts_local) {
			udp_act_clear(AF_INET6, p);
			s = up6[p].s;
		}
	}

	if (s != -1) {
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, s, NULL);
		close(s);
		sock_l4(c, af, IPPROTO_UDP, p);
	}
}

/**
 * udp_timer() - Scan activity bitmap for ports with associated timed events
 * @c:		Execution context
 * @ts:		Timestamp from caller
 */
void udp_timer(struct ctx *c, struct timespec *ts)
{
	long *word, tmp;
	unsigned int i;
	int n;

	word = (long *)udp4_act;
	for (i = 0; i < sizeof(udp4_act) / sizeof(long); i++, word++) {
		tmp = *word;
		while ((n = ffsl(tmp))) {
			tmp &= ~(1UL << (n - 1));
			udp_timer_one(c, AF_INET,
				      i * sizeof(long) * 8 + n - 1, ts);
		}
	}

	word = (long *)udp6_act;
	for (i = 0; i < sizeof(udp6_act) / sizeof(long); i++, word++) {
		tmp = *word;
		while ((n = ffsl(tmp))) {
			tmp &= ~(1UL << (n - 1));
			udp_timer_one(c, AF_INET6,
				      i * sizeof(long) * 8 + n - 1, ts);
		}
	}
}

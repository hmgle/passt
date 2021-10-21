// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * icmp.c - ICMP/ICMPv6 echo proxy
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#include "util.h"
#include "passt.h"
#include "tap.h"
#include "icmp.h"

#define ICMP_ECHO_TIMEOUT	60 /* s, timeout for ICMP socket activity */

/**
 * struct icmp_id_sock - Tracking information for single ICMP echo identifier
 * @sock:	Bound socket for identifier
 * @ts:		Last associated activity from tap, seconds
 * @seq:	Last sequence number sent to tap, host order
 */
struct icmp_id_sock {
	int sock;
	time_t ts;
	uint16_t seq;
};

/* Indexed by ICMP echo identifier */
static struct icmp_id_sock icmp_id_map	[IP_VERSIONS][USHRT_MAX];

/* Bitmaps, activity monitoring needed for identifier */
static uint8_t icmp_act			[IP_VERSIONS][USHRT_MAX / 8];

/**
 * icmp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp, unused
 */
void icmp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		       struct timespec *now)
{
	struct in6_addr a6 = { .s6_addr = {    0,    0,    0,    0,
					       0,    0,    0,    0,
					       0,    0, 0xff, 0xff,
					       0,    0,    0,    0 } };
	union icmp_epoll_ref *iref = &ref.r.p.icmp;
	struct sockaddr_storage sr;
	socklen_t sl = sizeof(sr);
	char buf[USHRT_MAX];
	uint16_t seq, id;
	ssize_t n;

	(void)events;
	(void)now;

	n = recvfrom(ref.r.s, buf, sizeof(buf), 0, (struct sockaddr *)&sr, &sl);
	if (n < 0)
		return;

	if (iref->icmp.v6) {
		struct sockaddr_in6 *sr6 = (struct sockaddr_in6 *)&sr;
		struct icmp6hdr *ih = (struct icmp6hdr *)buf;

		id = ntohs(ih->icmp6_identifier);

		/* If bind() fails e.g. because of a broken SELinux policy, this
		 * might happen. Fix up the identifier to match the sent one.
		 */
		if (id != iref->icmp.id)
			ih->icmp6_identifier = htons(iref->icmp.id);

		/* In PASTA mode, we'll get any reply we send, discard them. */
		if (c->mode == MODE_PASTA) {
			seq = ntohs(ih->icmp6_sequence);

			if (icmp_id_map[V6][id].seq == seq)
				return;

			icmp_id_map[V6][id].seq = seq;
		}

		tap_ip_send(c, &sr6->sin6_addr, IPPROTO_ICMPV6, buf, n, 0);
	} else {
		struct sockaddr_in *sr4 = (struct sockaddr_in *)&sr;
		struct icmphdr *ih = (struct icmphdr *)buf;

		id = ntohs(ih->un.echo.id);
		if (id != iref->icmp.id)
			ih->un.echo.id = htons(iref->icmp.id);

		if (c->mode == MODE_PASTA) {
			seq = ntohs(ih->un.echo.sequence);

			if (icmp_id_map[V4][id].seq == seq)
				return;

			icmp_id_map[V4][id].seq = seq;
		}

		memcpy(&a6.s6_addr[12], &sr4->sin_addr, sizeof(sr4->sin_addr));

		tap_ip_send(c, &a6, IPPROTO_ICMP, buf, n, 0);
	}
}

/**
 * icmp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @
 * @msg:	Input message
 * @count:	Message count (always 1 for ICMP)
 * @now:	Current timestamp
 *
 * Return: count of consumed packets (always 1, even if malformed)
 */
int icmp_tap_handler(struct ctx *c, int af, void *addr,
		     struct tap_l4_msg *msg, int count, struct timespec *now)
{
	(void)count;

	if (af == AF_INET) {
		union icmp_epoll_ref iref = { .icmp.v6 = 0 };
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr = { .s_addr = INADDR_ANY },
		};
		struct icmphdr *ih;
		int id, s;

		ih = (struct icmphdr *)(pkt_buf + msg[0].pkt_buf_offset);

		if (msg[0].l4_len < sizeof(*ih) || ih->type != ICMP_ECHO)
			return 1;

		sa.sin_port = ih->un.echo.id;

		iref.icmp.id = id = ntohs(ih->un.echo.id);

		if ((s = icmp_id_map[V4][id].sock) <= 0) {
			s = sock_l4(c, AF_INET, IPPROTO_ICMP, id, 0, iref.u32);
			if (s < 0)
				goto fail_sock;

			icmp_id_map[V4][id].sock = s;
		}
		icmp_id_map[V4][id].ts = now->tv_sec;
		bitmap_set(icmp_act[V4], id);

		sa.sin_addr = *(struct in_addr *)addr;
		sendto(s, ih, msg[0].l4_len, MSG_NOSIGNAL,
		       (struct sockaddr *)&sa, sizeof(sa));
	} else if (af == AF_INET6) {
		union icmp_epoll_ref iref = { .icmp.v6 = 1 };
		struct sockaddr_in6 sa = {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_ANY_INIT,
		};
		struct icmp6hdr *ih;
		int id, s;

		ih = (struct icmp6hdr *)(pkt_buf + msg[0].pkt_buf_offset);

		if (msg[0].l4_len < sizeof(*ih) ||
		    (ih->icmp6_type != 128 && ih->icmp6_type != 129))
			return 1;

		sa.sin6_port = ih->icmp6_identifier;

		iref.icmp.id = id = ntohs(ih->icmp6_identifier);
		if ((s = icmp_id_map[V6][id].sock) <= 0) {
			s = sock_l4(c, AF_INET6, IPPROTO_ICMPV6, id, 0,
				    iref.u32);
			if (s < 0)
				goto fail_sock;

			icmp_id_map[V6][id].sock = s;
		}
		icmp_id_map[V6][id].ts = now->tv_sec;
		bitmap_set(icmp_act[V6], id);

		sa.sin6_addr = *(struct in6_addr *)addr;
		sendto(s, ih, msg[0].l4_len, MSG_NOSIGNAL,
		       (struct sockaddr *)&sa, sizeof(sa));
	}

	return 1;

fail_sock:
	warn("Cannot open \"ping\" socket. You might need to:");
	warn("  sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"");
	warn("...echo requests/replies will fail.");
	return 1;
}

/**
 * icmp_timer_one() - Handler for timed events related to a given identifier
 * @c:		Execution context
 * @v6:		Set for IPv6 echo identifier bindings
 * @id:		Echo identifier, host order
 * @ts:		Timestamp from caller
 */
static void icmp_timer_one(struct ctx *c, int v6, uint16_t id,
			   struct timespec *ts)
{
	struct icmp_id_sock *id_map = &icmp_id_map[v6 ? V6 : V4][id];

	if (ts->tv_sec - id_map->ts <= ICMP_ECHO_TIMEOUT)
		return;

	bitmap_clear(icmp_act[v6 ? V6 : V4], id);

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, id_map->sock, NULL);
	close(id_map->sock);
	id_map->sock = 0;
}

/**
 * icmp_timer() - Scan activity bitmap for identifiers with timed events
 * @c:		Execution context
 * @ts:		Timestamp from caller
 */
void icmp_timer(struct ctx *c, struct timespec *ts)
{
	long *word, tmp;
	unsigned int i;
	int n, v6 = 0;

v6:
	word = (long *)icmp_act[v6 ? V6 : V4];
	for (i = 0; i < ARRAY_SIZE(icmp_act); i += sizeof(long), word++) {
		tmp = *word;
		while ((n = ffsl(tmp))) {
			tmp &= ~(1UL << (n - 1));
			icmp_timer_one(c, v6, i * 8 + n - 1, ts);
		}
	}

	if (!v6) {
		v6 = 1;
		goto v6;
	}
}

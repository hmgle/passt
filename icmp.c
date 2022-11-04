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

#include "packet.h"
#include "util.h"
#include "passt.h"
#include "tap.h"
#include "log.h"
#include "icmp.h"

#define ICMP_ECHO_TIMEOUT	60 /* s, timeout for ICMP socket activity */
#define ICMP_NUM_IDS		(1U << 16)

/**
 * struct icmp_id_sock - Tracking information for single ICMP echo identifier
 * @sock:	Bound socket for identifier
 * @seq:	Last sequence number sent to tap, host order, -1: not sent yet
 * @ts:		Last associated activity from tap, seconds
 */
struct icmp_id_sock {
	int sock;
	int seq;
	time_t ts;
};

/* Indexed by ICMP echo identifier */
static struct icmp_id_sock icmp_id_map[IP_VERSIONS][ICMP_NUM_IDS];

/* Bitmaps, activity monitoring needed for identifier */
static uint8_t icmp_act[IP_VERSIONS][DIV_ROUND_UP(ICMP_NUM_IDS, 8)];

/**
 * icmp_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp, unused
 */
void icmp_sock_handler(const struct ctx *c, union epoll_ref ref,
		       uint32_t events, const struct timespec *now)
{
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
		seq = ntohs(ih->icmp6_sequence);

		/* If bind() fails e.g. because of a broken SELinux policy, this
		 * might happen. Fix up the identifier to match the sent one.
		 */
		if (id != iref->icmp.id)
			ih->icmp6_identifier = htons(iref->icmp.id);

		/* In PASTA mode, we'll get any reply we send, discard them. */
		if (c->mode == MODE_PASTA) {
			if (icmp_id_map[V6][id].seq == seq)
				return;

			icmp_id_map[V6][id].seq = seq;
		}

		debug("ICMPv6: echo %s to tap, ID: %i, seq: %i",
		      (ih->icmp6_type == 128) ? "request" : "reply", id, seq);

		tap_icmp6_send(c, &sr6->sin6_addr,
			       tap_ip6_daddr(c, &sr6->sin6_addr), buf, n);
	} else {
		struct sockaddr_in *sr4 = (struct sockaddr_in *)&sr;
		struct icmphdr *ih = (struct icmphdr *)buf;

		id = ntohs(ih->un.echo.id);
		seq = ntohs(ih->un.echo.sequence);

		if (id != iref->icmp.id)
			ih->un.echo.id = htons(iref->icmp.id);

		if (c->mode == MODE_PASTA) {

			if (icmp_id_map[V4][id].seq == seq)
				return;

			icmp_id_map[V4][id].seq = seq;
		}

		debug("ICMP: echo %s to tap, ID: %i, seq: %i",
		      (ih->type == ICMP_ECHO) ? "request" : "reply", id, seq);

		tap_icmp4_send(c, sr4->sin_addr, tap_ip4_daddr(c), buf, n);
	}
}

/**
 * icmp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @addr:	Destination address
 * @p:		Packet pool, single packet with ICMP/ICMPv6 header
 * @now:	Current timestamp
 *
 * Return: count of consumed packets (always 1, even if malformed)
 */
int icmp_tap_handler(const struct ctx *c, int af, const void *addr,
		     const struct pool *p, const struct timespec *now)
{
	size_t plen;

	if (af == AF_INET) {
		union icmp_epoll_ref iref = { .icmp.v6 = 0 };
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr = { .s_addr = htonl(INADDR_ANY) },
		};
		struct icmphdr *ih;
		int id, s;

		ih = packet_get(p, 0, 0, sizeof(*ih), &plen);
		if (!ih)
			return 1;

		if (ih->type != ICMP_ECHO && ih->type != ICMP_ECHOREPLY)
			return 1;

		sa.sin_port = ih->un.echo.id;

		iref.icmp.id = id = ntohs(ih->un.echo.id);

		if ((s = icmp_id_map[V4][id].sock) <= 0) {
			s = sock_l4(c, AF_INET, IPPROTO_ICMP, NULL, NULL, id,
				    iref.u32);
			if (s < 0)
				goto fail_sock;
			if (s > SOCKET_MAX) {
				close(s);
				return 1;
			}

			icmp_id_map[V4][id].sock = s;

			debug("ICMP: new socket %i for echo ID %i", s, id);
		}
		icmp_id_map[V4][id].ts = now->tv_sec;
		bitmap_set(icmp_act[V4], id);

		sa.sin_addr = *(struct in_addr *)addr;
		if (sendto(s, ih, sizeof(*ih) + plen, MSG_NOSIGNAL,
			   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			debug("ICMP: failed to relay request to socket");
		} else {
			debug("ICMP: echo %s to socket, ID: %i, seq: %i",
			      (ih->type == ICMP_ECHO) ? "request" : "reply",
			      id, ntohs(ih->un.echo.sequence));
		}
	} else if (af == AF_INET6) {
		union icmp_epoll_ref iref = { .icmp.v6 = 1 };
		struct sockaddr_in6 sa = {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_ANY_INIT,
			.sin6_scope_id = c->ifi6,
		};
		struct icmp6hdr *ih;
		int id, s;

		ih = packet_get(p, 0, 0, sizeof(struct icmp6hdr), &plen);
		if (!ih)
			return 1;

		if (ih->icmp6_type != 128 && ih->icmp6_type != 129)
			return 1;

		sa.sin6_port = ih->icmp6_identifier;

		iref.icmp.id = id = ntohs(ih->icmp6_identifier);
		if ((s = icmp_id_map[V6][id].sock) <= 0) {
			s = sock_l4(c, AF_INET6, IPPROTO_ICMPV6, NULL, NULL, id,
				    iref.u32);
			if (s < 0)
				goto fail_sock;
			if (s > SOCKET_MAX) {
				close(s);
				return 1;
			}

			icmp_id_map[V6][id].sock = s;

			debug("ICMPv6: new socket %i for echo ID %i", s, id);
		}
		icmp_id_map[V6][id].ts = now->tv_sec;
		bitmap_set(icmp_act[V6], id);

		sa.sin6_addr = *(struct in6_addr *)addr;
		if (sendto(s, ih, sizeof(*ih) + plen, MSG_NOSIGNAL,
			   (struct sockaddr *)&sa, sizeof(sa)) < 1) {
			debug("ICMPv6: failed to relay request to socket");
		} else {
			debug("ICMPv6: echo %s to socket, ID: %i, seq: %i",
			      (ih->icmp6_type == 128) ? "request" : "reply",
			      id, ntohs(ih->icmp6_sequence));
		}
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
static void icmp_timer_one(const struct ctx *c, int v6, uint16_t id,
			   const struct timespec *ts)
{
	struct icmp_id_sock *id_map = &icmp_id_map[v6 ? V6 : V4][id];

	if (ts->tv_sec - id_map->ts <= ICMP_ECHO_TIMEOUT)
		return;

	bitmap_clear(icmp_act[v6 ? V6 : V4], id);

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, id_map->sock, NULL);
	close(id_map->sock);
	id_map->sock = 0;
	id_map->seq = -1;
}

/**
 * icmp_timer() - Scan activity bitmap for identifiers with timed events
 * @c:		Execution context
 * @ts:		Timestamp from caller
 */
void icmp_timer(const struct ctx *c, const struct timespec *ts)
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

/**
 * icmp_init() - Initialise sequences in ID map to -1 (no sequence sent yet)
 */
void icmp_init(void)
{
	unsigned i;

	for (i = 0; i < ICMP_NUM_IDS; i++)
		icmp_id_map[V4][i].seq = icmp_id_map[V6][i].seq = -1;
}

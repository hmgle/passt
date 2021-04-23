// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *
 * util.c - Convenience helpers
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <syslog.h>
#include <stdarg.h>

#include "passt.h"

#define logfn(name, level)						\
void name(const char *format, ...) {					\
	va_list args;							\
									\
	va_start(args, format);						\
	vsyslog(level, format, args);					\
	va_end(args);							\
}

logfn(err,   LOG_ERR)
logfn(warn,  LOG_WARNING)
logfn(info,  LOG_INFO)
#ifdef DEBUG
logfn(debug, LOG_DEBUG)
#endif

/**
 * csum_fold() - Fold long sum for IP and TCP checksum
 * @sum:	Original long sum
 *
 * Return: 16-bit folded sum
 */
uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

/**
 * csum_ipv4() - Calculate IPv4 checksum
 * @buf:	Packet buffer, L3 headers
 * @len:	Total L3 packet length
 *
 * Return: 16-bit IPv4-style checksum
 */
uint16_t csum_ip4(void *buf, size_t len)
{
	uint32_t sum = 0;
	uint16_t *p = buf;
	size_t len1 = len / 2;
	size_t off;

	for (off = 0; off < len1; off++, p++)
		sum += *p;

	if (len % 2)
		sum += *p & 0xff;

	return ~csum_fold(sum);
}

/**
 * csum_ipv4() - Calculate TCP checksum for IPv4 and set in place
 * @iph:	Packet buffer, IP header
 */
void csum_tcp4(struct iphdr *iph)
{
	struct tcphdr *th = (struct tcphdr *)((char *)iph + iph->ihl * 4);
	uint16_t tlen = ntohs(iph->tot_len) - iph->ihl * 4, *p = (uint16_t *)th;
	uint32_t sum = 0;

	sum += (iph->saddr >> 16) & 0xffff;
	sum += iph->saddr & 0xffff;
	sum += (iph->daddr >> 16) & 0xffff;
	sum += iph->daddr & 0xffff;

	sum += htons(IPPROTO_TCP);
	sum += htons(tlen);

	th->check = 0;
	while (tlen > 1) {
		sum += *p++;
		tlen -= 2;
	}

	if (tlen > 0) {
		sum += *p & htons(0xff00);
	}

	th->check = (uint16_t)~csum_fold(sum);
}

/**
 * ipv6_l4hdr() - Find pointer to L4 header in IPv6 packet and extract protocol
 * @ip6h:	IPv6 header
 * @proto:	Filled with L4 protocol number
 *
 * Return: pointer to L4 header, NULL if not found
 */
char *ipv6_l4hdr(struct ipv6hdr *ip6h, uint8_t *proto)
{
	int offset, len, hdrlen;
	struct ipv6_opt_hdr *o;
	uint8_t nh;

	len = ntohs(ip6h->payload_len);
	offset = 0;

	while (offset < len) {
		if (!offset) {
			nh = ip6h->nexthdr;
			hdrlen = sizeof(struct ipv6hdr);
		} else {
			nh = o->nexthdr;
			hdrlen = (o->hdrlen + 1) * 8;
		}

		if (nh == 59)
			return NULL;

		if (nh == 0   || nh == 43  || nh == 44  || nh == 50  ||
		    nh == 51  || nh == 60  || nh == 135 || nh == 139 ||
		    nh == 140 || nh == 253 || nh == 254) {
			offset += hdrlen;
			o = (struct ipv6_opt_hdr *)(unsigned char *)ip6h +
								    offset;
		} else {
			*proto = nh;
			return (char *)(ip6h + 1) + offset;
		}
	}

	return NULL;
}

/**
 * sock_l4_add() - Create and bind socket for given L4, add to epoll list
 * @c:		Execution context
 * @v:		IP protocol, 4 or 6
 * @proto:	Protocol number, host order
 * @port:	Port, network order
 *
 * Return: newly created socket, -1 on error
 */
int sock_l4_add(struct ctx *c, int v, uint16_t proto, uint16_t port)
{
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr = { .s_addr = INADDR_ANY },
	};
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	struct epoll_event ev = { 0 };
	const struct sockaddr *sa;
	int fd, sl, one = 1;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	    proto != IPPROTO_ICMP && proto != IPPROTO_ICMPV6)
		return -1;	/* Not implemented. */

	fd = socket(v == 4 ? AF_INET : AF_INET6,
		    proto == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, proto);
	if (fd < 0) {
		perror("L4 socket");
		return -1;
	}

#define CHECK_SET_MIN_MAX(ipproto, proto_ctx, fd)			\
	if (proto == (ipproto)) {					\
		if (fd < c->proto_ctx.fd_min)				\
			c->proto_ctx.fd_min = (fd);			\
		if (fd > c->proto_ctx.fd_max)				\
			c->proto_ctx.fd_max = (fd);			\
	}

	CHECK_SET_MIN_MAX(IPPROTO_ICMP,		icmp,	fd);
	CHECK_SET_MIN_MAX(IPPROTO_ICMPV6,	icmp,	fd);
	CHECK_SET_MIN_MAX(IPPROTO_TCP,		tcp,	fd);
	CHECK_SET_MIN_MAX(IPPROTO_UDP,		udp,	fd);

#undef CHECK_SET_MIN_MAX

	if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)
		goto epoll_add;

	if (v == 4) {
		sa = (const struct sockaddr *)&addr4;
		sl = sizeof(addr4);
	} else {
		sa = (const struct sockaddr *)&addr6;
		sl = sizeof(addr6);

		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	}

	if (bind(fd, sa, sl) < 0) {
		/* We'll fail to bind to low ports if we don't have enough
		 * capabilities, and we'll fail to bind on already bound ports,
		 * this is fine.
		 */
		close(fd);
		return 0;
	}

	if (proto == IPPROTO_TCP && listen(fd, 128) < 0) {
		perror("TCP socket listen");
		close(fd);
		return -1;
	}

epoll_add:
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		perror("L4 epoll_ctl");
		return -1;
	}

	return fd;
}

/**
 * timespec_diff_ms() - Report difference in milliseconds between two timestamps
 * @a:		Minuend timestamp
 * @b:		Subtrahend timestamp
 *
 * Return: difference in milliseconds
 */
int timespec_diff_ms(struct timespec *a, struct timespec *b)
{
	if (a->tv_nsec < b->tv_nsec) {
		return (b->tv_nsec - a->tv_nsec) / 1000000 +
		       (a->tv_sec - b->tv_sec - 1) * 1000;
	}

	return (a->tv_nsec - b->tv_nsec) / 1000000 +
	       (a->tv_sec - b->tv_sec) * 1000;
}

// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tap.c - Functions to communicate with guest- or namespace-facing interface
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 */

#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

#include <linux/if_tun.h>
#include <linux/icmpv6.h>

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "arp.h"
#include "dhcp.h"
#include "ndp.h"
#include "dhcpv6.h"
#include "pcap.h"
#include "netlink.h"
#include "pasta.h"
#include "packet.h"

/* IPv4 (plus ARP) and IPv6 message batches from tap/guest to IP handlers */
static PACKET_POOL_NOINIT(pool_tap4, TAP_MSGS, pkt_buf);
static PACKET_POOL_NOINIT(pool_tap6, TAP_MSGS, pkt_buf);

#define TAP_SEQS		128 /* Different L4 tuples in one batch */

/**
 * tap_send() - Send frame, with qemu socket header if needed
 * @c:		Execution context
 * @data:	Packet buffer
 * @len:	Total L2 packet length
 * @vnet_pre:	Buffer has four-byte headroom
 *
 * Return: return code from send() or write()
 */
int tap_send(const struct ctx *c, const void *data, size_t len, int vnet_pre)
{
	if (vnet_pre)
		pcap((char *)data + 4, len);
	else
		pcap(data, len);

	if (c->mode == MODE_PASST) {
		int flags = MSG_NOSIGNAL | MSG_DONTWAIT;

		if (vnet_pre) {
			*((uint32_t *)data) = htonl(len);
			len += 4;
		} else {
			uint32_t vnet_len = htonl(len);

			if (send(c->fd_tap, &vnet_len, 4, flags) < 0)
				return -1;
		}

		return send(c->fd_tap, data, len, flags);
	}

	return write(c->fd_tap, (char *)data + (vnet_pre ? 4 : 0), len);
}

/**
 * tap_ip_send() - Send IP packet, with L2 headers, calculating L3/L4 checksums
 * @c:		Execution context
 * @src:	IPv6 source address, IPv4-mapped for IPv4 sources
 * @proto:	L4 protocol number
 * @in:		Payload
 * @len:	L4 payload length
 * @flow:	Flow label for TCP over IPv6
 */
void tap_ip_send(const struct ctx *c, const struct in6_addr *src, uint8_t proto,
		 const char *in, size_t len, uint32_t flow)
{
	char buf[USHRT_MAX];
	char *pkt = buf + 4;
	struct ethhdr *eh;

	eh = (struct ethhdr *)pkt;

	/* TODO: ARP table lookup */
	memcpy(eh->h_dest, c->mac_guest, ETH_ALEN);
	memcpy(eh->h_source, c->mac, ETH_ALEN);

	if (IN6_IS_ADDR_V4MAPPED(src)) {
		struct iphdr *iph = (struct iphdr *)(eh + 1);
		char *data = (char *)(iph + 1);

		eh->h_proto = ntohs(ETH_P_IP);

		iph->version = 4;
		iph->ihl = 5;
		iph->tos = 0;
		iph->tot_len = htons(len + 20);
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 255;
		iph->protocol = proto;
		iph->daddr = c->addr4_seen;
		memcpy(&iph->saddr, &src->s6_addr[12], 4);

		iph->check = 0;
		iph->check = csum_unaligned(iph, (size_t)iph->ihl * 4, 0);

		memcpy(data, in, len);

		if (iph->protocol == IPPROTO_TCP) {
			csum_tcp4(iph);
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *uh = (struct udphdr *)(iph + 1);

			uh->check = 0;
		} else if (iph->protocol == IPPROTO_ICMP) {
			struct icmphdr *ih = (struct icmphdr *)(iph + 1);

			ih->checksum = 0;
			ih->checksum = csum_unaligned(ih, len, 0);
		}

		if (tap_send(c, buf, len + sizeof(*iph) + sizeof(*eh), 1) < 0)
			debug("tap: failed to send %lu bytes (IPv4)", len);
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
		char *data = (char *)(ip6h + 1);

		eh->h_proto = ntohs(ETH_P_IPV6);

		memset(ip6h->flow_lbl, 0, 3);
		ip6h->payload_len = htons(len);
		ip6h->priority = 0;

		ip6h->saddr = *src;
		if (IN6_IS_ADDR_LINKLOCAL(src))
			ip6h->daddr = c->addr6_ll_seen;
		else
			ip6h->daddr = c->addr6_seen;

		memcpy(data, in, len);

		ip6h->hop_limit = proto;
		ip6h->version = 0;
		ip6h->nexthdr = 0;
		if (proto == IPPROTO_TCP) {
			struct tcphdr *th = (struct tcphdr *)(ip6h + 1);

			th->check = 0;
			th->check = csum_unaligned(ip6h, len + sizeof(*ip6h),
						   0);
		} else if (proto == IPPROTO_UDP) {
			struct udphdr *uh = (struct udphdr *)(ip6h + 1);

			uh->check = 0;
			uh->check = csum_unaligned(ip6h, len + sizeof(*ip6h),
						   0);
		} else if (proto == IPPROTO_ICMPV6) {
			struct icmp6hdr *ih = (struct icmp6hdr *)(ip6h + 1);

			ih->icmp6_cksum = 0;
			ih->icmp6_cksum = csum_unaligned(ip6h,
							 len + sizeof(*ip6h),
							 0);
		}
		ip6h->version = 6;
		ip6h->nexthdr = proto;
		ip6h->hop_limit = 255;
		if (flow) {
			ip6h->flow_lbl[0] = (flow >> 16) & 0xf;
			ip6h->flow_lbl[1] = (flow >> 8) & 0xff;
			ip6h->flow_lbl[2] = (flow >> 0) & 0xff;
		}

		if (tap_send(c, buf, len + sizeof(*ip6h) + sizeof(*eh), 1) < 1)
			debug("tap: failed to send %lu bytes (IPv6)", len);
	}
}

PACKET_POOL_DECL(pool_l4, UIO_MAXIOV, pkt_buf);

/**
 * struct l4_seq4_t - Message sequence for one protocol handler call, IPv4
 * @msgs:	Count of messages in sequence
 * @protocol:	Protocol number
 * @source:	Source port
 * @dest:	Destination port
 * @saddr:	Source address
 * @daddr:	Destination address
 * @msg:	Array of messages that can be handled in a single call
 */
static struct tap4_l4_t {
	uint8_t protocol;

	uint16_t source;
	uint16_t dest;

	uint32_t saddr;
	uint32_t daddr;

	struct pool_l4_t p;
} tap4_l4[TAP_SEQS /* Arbitrary: TAP_MSGS in theory, so limit in users */];

/**
 * struct l4_seq6_t - Message sequence for one protocol handler call, IPv6
 * @msgs:	Count of messages in sequence
 * @protocol:	Protocol number
 * @source:	Source port
 * @dest:	Destination port
 * @saddr:	Source address
 * @daddr:	Destination address
 * @msg:	Array of messages that can be handled in a single call
 */
static struct tap6_l4_t {
	uint8_t protocol;

	uint16_t source;
	uint16_t dest;

	struct in6_addr saddr;
	struct in6_addr daddr;

	struct pool_l4_t p;
} tap6_l4[TAP_SEQS /* Arbitrary: TAP_MSGS in theory, so limit in users */];

/**
 * tap_packet_debug() - Print debug message for packet(s) from guest/tap
 * @iph:	IPv4 header, can be NULL
 * @ip6h:	IPv6 header, can be NULL
 * @seq4:	Pointer to @struct tap_l4_seq4, can be NULL
 * @proto6:	IPv6 protocol, for IPv6
 * @seq6:	Pointer to @struct tap_l4_seq6, can be NULL
 * @count:	Count of packets in this sequence
 */
static void tap_packet_debug(const struct iphdr *iph,
			     const struct ipv6hdr *ip6h,
			     const struct tap4_l4_t *seq4, uint8_t proto6,
			     const struct tap6_l4_t *seq6, int count)
{
	char buf6s[INET6_ADDRSTRLEN], buf6d[INET6_ADDRSTRLEN];
	char buf4s[INET_ADDRSTRLEN], buf4d[INET_ADDRSTRLEN];
	uint8_t proto = 0;

	if (iph || seq4) {
		inet_ntop(AF_INET,   iph ? &iph->saddr  : &seq4->saddr,
			  buf4s, sizeof(buf4s));
		inet_ntop(AF_INET,   iph ? &iph->daddr  : &seq4->daddr,
			  buf4d, sizeof(buf4d));
		if (iph)
			proto = iph->protocol;
		else if (seq4)
			proto = seq4->protocol;
	} else {
		inet_ntop(AF_INET6, ip6h ? &ip6h->saddr : &seq6->saddr,
			  buf6s, sizeof(buf6s));
		inet_ntop(AF_INET6, ip6h ? &ip6h->daddr : &seq6->daddr,
			  buf6d, sizeof(buf6d));
		proto = proto6;
	}

	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		trace("tap: protocol %i, %s%s%s:%i -> %s%s%s:%i (%i packet%s)",
		      proto,
		      seq4 ? "" : "[", seq4 ? buf4s : buf6s, seq4 ? "" : "]",
		      ntohs(seq4 ? seq4->source : seq6->source),
		      seq4 ? "" : "[", seq4 ? buf4d : buf6d, seq4 ? "" : "]",
		      ntohs(seq4 ? seq4->dest : seq6->dest),
		      count, count == 1 ? "" : "s");
	} else {
		trace("tap: protocol %i, %s -> %s (%i packet%s)",
		      proto, iph ? buf4s : buf6s, iph ? buf4d : buf6d,
		      count, count == 1 ? "" : "s");
	}
}

/**
 * tap4_handler() - IPv4 and ARP packet handler for tap file descriptor
 * @c:		Execution context
 * @in:		Ingress packet pool, packets with Ethernet headers
 * @now:	Current timestamp
 *
 * Return: count of packets consumed by handlers
 */
static int tap4_handler(struct ctx *c, const struct pool *in,
			const struct timespec *now)
{
	unsigned int i, j, seq_count;
	struct tap4_l4_t *seq;

	if (!c->v4 || !in->count)
		return in->count;

	i = 0;
resume:
	for (seq_count = 0, seq = NULL; i < in->count; i++) {
		size_t l2_len, l3_len, hlen, l4_len;
		struct ethhdr *eh;
		struct iphdr *iph;
		struct udphdr *uh;
		char *l4h;

		packet_get(in, i, 0, 0, &l2_len);

		eh = packet_get(in, i, 0, sizeof(*eh), &l3_len);
		if (!eh)
			continue;
		if (ntohs(eh->h_proto) == ETH_P_ARP) {
			PACKET_POOL_P(pkt, 1, in->buf, sizeof(pkt_buf));

			packet_add(pkt, l2_len, (char *)eh);
			arp(c, pkt);
			continue;
		}

		iph = packet_get(in, i, sizeof(*eh), sizeof(*iph), NULL);
		if (!iph)
			continue;

		hlen = iph->ihl * 4UL;
		if (hlen < sizeof(*iph) || htons(iph->tot_len) != l3_len ||
		    hlen > l3_len)
			continue;

		l4_len = l3_len - hlen;

		if (iph->saddr && c->addr4_seen != iph->saddr) {
			c->addr4_seen = iph->saddr;
			proto_update_l2_buf(NULL, NULL, &c->addr4_seen);
		}

		l4h = packet_get(in, i, sizeof(*eh) + hlen, l4_len, NULL);
		if (!l4h)
			continue;

		if (iph->protocol == IPPROTO_ICMP) {
			PACKET_POOL_P(pkt, 1, in->buf, sizeof(pkt_buf));

			if (c->no_icmp)
				continue;

			packet_add(pkt, l4_len, l4h);
			icmp_tap_handler(c, AF_INET, &iph->daddr, pkt, now);
			continue;
		}

		uh = packet_get(in, i, sizeof(*eh) + hlen, sizeof(*uh), NULL);
		if (!uh)
			continue;

		if (iph->protocol == IPPROTO_UDP) {
			PACKET_POOL_P(pkt, 1, in->buf, sizeof(pkt_buf));

			packet_add(pkt, l2_len, (char *)eh);
			if (dhcp(c, pkt))
				continue;
		}

		if (iph->protocol != IPPROTO_TCP &&
		    iph->protocol != IPPROTO_UDP) {
			tap_packet_debug(iph, NULL, NULL, 0, NULL, 1);
			continue;
		}

#define L4_MATCH(iph, uh, seq)						\
	(seq->protocol == iph->protocol &&				\
	 seq->source   == uh->source    && seq->dest  == uh->dest &&	\
	 seq->saddr    == iph->saddr    && seq->daddr == iph->daddr)

#define L4_SET(iph, uh, seq)						\
	do {								\
		seq->protocol	= iph->protocol;			\
		seq->source	= uh->source;				\
		seq->dest	= uh->dest;				\
		seq->saddr	= iph->saddr;				\
		seq->daddr	= iph->daddr;				\
	} while (0)

		if (seq && L4_MATCH(iph, uh, seq) && seq->p.count < TAP_SEQS)
			goto append;

		for (seq = tap4_l4 + seq_count - 1; seq >= tap4_l4; seq--) {
			if (L4_MATCH(iph, uh, seq)) {
				if (seq->p.count >= TAP_SEQS)
					seq = NULL;
				break;
			}
		}

		if (!seq || seq < tap4_l4) {
			seq = tap4_l4 + seq_count++;
			L4_SET(iph, uh, seq);
			pool_flush((struct pool *)&seq->p);
		}

#undef L4_MATCH
#undef L4_SET

append:
		packet_add((struct pool *)&seq->p, l4_len, l4h);

		if (seq_count == TAP_SEQS)
			break;	/* Resume after flushing if i < count */
	}

	for (j = 0, seq = tap4_l4; j < seq_count; j++, seq++) {
		struct pool *p = (struct pool *)&seq->p;
		uint32_t *da = &seq->daddr;
		size_t n = p->count;

		tap_packet_debug(NULL, NULL, seq, 0, NULL, n);

		if (seq->protocol == IPPROTO_TCP) {
			if (c->no_tcp)
				continue;
			while ((n -= tcp_tap_handler(c, AF_INET, da, p, now)));
		} else if (seq->protocol == IPPROTO_UDP) {
			if (c->no_udp)
				continue;
			while ((n -= udp_tap_handler(c, AF_INET, da, p, now)));
		}
	}

	if (i < in->count)
		goto resume;

	return in->count;
}

/**
 * tap6_handler() - IPv6 packet handler for tap file descriptor
 * @c:		Execution context
 * @in:		Ingress packet pool, packets with Ethernet headers
 * @now:	Current timestamp
 *
 * Return: count of packets consumed by handlers
 */
static int tap6_handler(struct ctx *c, const struct pool *in,
			const struct timespec *now)
{
	unsigned int i, j, seq_count = 0;
	struct tap6_l4_t *seq;

	if (!c->v6 || !in->count)
		return in->count;

	i = 0;
resume:
	for (seq_count = 0, seq = NULL; i < in->count; i++) {
		size_t l4_len, plen, check;
		struct in6_addr *saddr, *daddr;
		struct ipv6hdr *ip6h;
		struct ethhdr *eh;
		struct udphdr *uh;
		uint8_t proto;
		char *l4h;

		eh =   packet_get(in, i, 0,		sizeof(*eh), NULL);
		if (!eh)
			continue;

		ip6h = packet_get(in, i, sizeof(*eh),	sizeof(*ip6h), &check);
		if (!ip6h)
			continue;

		saddr = &ip6h->saddr;
		daddr = &ip6h->daddr;

		plen = ntohs(ip6h->payload_len);
		if (plen != check)
			continue;

		if (!(l4h = ipv6_l4hdr(in, i, sizeof(*eh), &proto, &l4_len)))
			continue;

		if (IN6_IS_ADDR_LINKLOCAL(saddr)) {
			c->addr6_ll_seen = *saddr;

			if (IN6_IS_ADDR_UNSPECIFIED(&c->addr6_seen)) {
				c->addr6_seen = *saddr;
			}
		} else {
			c->addr6_seen = *saddr;
		}

		if (proto == IPPROTO_ICMPV6) {
			PACKET_POOL_P(pkt, 1, in->buf, sizeof(pkt_buf));

			if (c->no_icmp)
				continue;

			if (l4_len < sizeof(struct icmp6hdr))
				continue;

			if (ndp(c, (struct icmp6hdr *)l4h, eh->h_source, saddr))
				continue;

			tap_packet_debug(NULL, ip6h, NULL, proto, NULL, 1);

			packet_add(pkt, l4_len, l4h);
			icmp_tap_handler(c, AF_INET6, daddr, pkt, now);
			continue;
		}

		if (l4_len < sizeof(*uh))
			continue;
		uh = (struct udphdr *)l4h;

		if (proto == IPPROTO_UDP) {
			PACKET_POOL_P(pkt, 1, in->buf, sizeof(pkt_buf));

			packet_add(pkt, l4_len, l4h);

			if (dhcpv6(c, pkt, saddr, daddr))
				continue;
		}

		*saddr = c->addr6;

		if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
			tap_packet_debug(NULL, ip6h, NULL, proto, NULL, 1);
			continue;
		}

#define L4_MATCH(ip6h, proto, uh, seq)					\
	(seq->protocol == proto         &&				\
	 seq->source   == uh->source    && seq->dest  == uh->dest &&	\
	 IN6_ARE_ADDR_EQUAL(&seq->saddr, saddr)			  &&	\
	 IN6_ARE_ADDR_EQUAL(&seq->daddr, daddr))

#define L4_SET(ip6h, proto, uh, seq)					\
	do {								\
		seq->protocol	= proto;				\
		seq->source	= uh->source;				\
		seq->dest	= uh->dest;				\
		seq->saddr	= *saddr;				\
		seq->daddr	= *daddr;				\
	} while (0)

		if (seq && L4_MATCH(ip6h, proto, uh, seq) &&
		    seq->p.count < TAP_SEQS)
			goto append;

		for (seq = tap6_l4 + seq_count - 1; seq >= tap6_l4; seq--) {
			if (L4_MATCH(ip6h, proto, uh, seq)) {
				if (seq->p.count >= TAP_SEQS)
					seq = NULL;
				break;
			}
		}

		if (!seq || seq < tap6_l4) {
			seq = tap6_l4 + seq_count++;
			L4_SET(ip6h, proto, uh, seq);
			pool_flush((struct pool *)&seq->p);
		}

#undef L4_MATCH
#undef L4_SET

append:
		packet_add((struct pool *)&seq->p, l4_len, l4h);

		if (seq_count == TAP_SEQS)
			break;	/* Resume after flushing if i < count */
	}

	for (j = 0, seq = tap6_l4; j < seq_count; j++, seq++) {
		struct pool *p = (struct pool *)&seq->p;
		struct in6_addr *da = &seq->daddr;
		size_t n = p->count;

		tap_packet_debug(NULL, NULL, NULL, seq->protocol, seq, n);

		if (seq->protocol == IPPROTO_TCP) {
			if (c->no_tcp)
				continue;
			while ((n -= tcp_tap_handler(c, AF_INET6, da, p, now)));
		} else if (seq->protocol == IPPROTO_UDP) {
			if (c->no_udp)
				continue;
			while ((n -= udp_tap_handler(c, AF_INET6, da, p, now)));
		}
	}

	if (i < in->count)
		goto resume;

	return in->count;
}

/**
 * tap_handler_passt() - Packet handler for AF_UNIX file descriptor
 * @c:		Execution context
 * @now:	Current timestamp
 *
 * Return: -ECONNRESET on receive error, 0 otherwise
 */
static int tap_handler_passt(struct ctx *c, const struct timespec *now)
{
	struct ethhdr *eh;
	ssize_t n, rem;
	char *p;

redo:
	p = pkt_buf;
	rem = 0;

	pool_flush(pool_tap4);
	pool_flush(pool_tap6);

	n = recv(c->fd_tap, p, TAP_BUF_FILL, MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_tap, NULL);
		close(c->fd_tap);

		return -ECONNRESET;
	}

	while (n > (ssize_t)sizeof(uint32_t)) {
		ssize_t len = ntohl(*(uint32_t *)p);

		p += sizeof(uint32_t);
		n -= sizeof(uint32_t);

		/* At most one packet might not fit in a single read, and this
		 * needs to be blocking.
		 */
		if (len > n) {
			rem = recv(c->fd_tap, p + n, len - n, 0);
			if ((n += rem) != len)
				return 0;
		}

		/* Complete the partial read above before discarding a malformed
		 * frame, otherwise the stream will be inconsistent.
		 */
		if (len < (ssize_t)sizeof(*eh) || len > (ssize_t)ETH_MAX_MTU)
			goto next;

		pcap(p, len);

		eh = (struct ethhdr *)p;

		if (memcmp(c->mac_guest, eh->h_source, ETH_ALEN)) {
			memcpy(c->mac_guest, eh->h_source, ETH_ALEN);
			proto_update_l2_buf(c->mac_guest, NULL, NULL);
		}

		switch (ntohs(eh->h_proto)) {
		case ETH_P_ARP:
		case ETH_P_IP:
			packet_add(pool_tap4, len, p);
			break;
		case ETH_P_IPV6:
			packet_add(pool_tap6, len, p);
			break;
		default:
			break;
		}

next:
		p += len;
		n -= len;
	}

	tap4_handler(c, pool_tap4, now);
	tap6_handler(c, pool_tap6, now);

	/* We can't use EPOLLET otherwise. */
	if (rem)
		goto redo;

	return 0;
}

/**
 * tap_handler_pasta() - Packet handler for tuntap file descriptor
 * @c:		Execution context
 * @now:	Current timestamp
 *
 * Return: -ECONNRESET on receive error, 0 otherwise
 */
static int tap_handler_pasta(struct ctx *c, const struct timespec *now)
{
	ssize_t n, len;
	int ret;

redo:
	n = 0;

	pool_flush(pool_tap4);
	pool_flush(pool_tap6);
restart:
	while ((len = read(c->fd_tap, pkt_buf + n, TAP_BUF_BYTES - n)) > 0) {
		struct ethhdr *eh = (struct ethhdr *)(pkt_buf + n);

		if (len < (ssize_t)sizeof(*eh) || len > (ssize_t)ETH_MAX_MTU) {
			n += len;
			continue;
		}

		pcap(pkt_buf + n, len);

		if (memcmp(c->mac_guest, eh->h_source, ETH_ALEN)) {
			memcpy(c->mac_guest, eh->h_source, ETH_ALEN);
			proto_update_l2_buf(c->mac_guest, NULL, NULL);
		}

		switch (ntohs(eh->h_proto)) {
		case ETH_P_ARP:
		case ETH_P_IP:
			packet_add(pool_tap4, len, pkt_buf + n);
			break;
		case ETH_P_IPV6:
			packet_add(pool_tap6, len, pkt_buf + n);
			break;
		default:
			break;
		}

		if ((n += len) == TAP_BUF_BYTES)
			break;
	}

	if (len < 0 && errno == EINTR)
		goto restart;

	ret = errno;

	tap4_handler(c, pool_tap4, now);
	tap6_handler(c, pool_tap6, now);

	if (len > 0 || ret == EAGAIN)
		return 0;

	if (n == TAP_BUF_BYTES)
		goto redo;

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_tap, NULL);
	close(c->fd_tap);

	return -ECONNRESET;
}

/**
 * tap_sock_unix_init() - Create and bind AF_UNIX socket, listen for connection
 * @c:		Execution context
 */
static void tap_sock_unix_init(struct ctx *c)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0), ex;
	struct epoll_event ev = { 0 };
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	int i, ret;

	if (fd < 0) {
		perror("UNIX socket");
		exit(EXIT_FAILURE);
	}

	for (i = 1; i < UNIX_SOCK_MAX; i++) {
		char *path = addr.sun_path;

		if (*c->sock_path)
			strncpy(path, c->sock_path, UNIX_PATH_MAX);
		else
			snprintf(path, UNIX_PATH_MAX, UNIX_SOCK_PATH, i);

		ex = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
		ret = connect(ex, (const struct sockaddr *)&addr, sizeof(addr));
		if (!ret || (errno != ENOENT && errno != ECONNREFUSED)) {
			if (*c->sock_path) {
				err("Socket path %s already in use", path);
				exit(EXIT_FAILURE);
			}

			close(ex);
			continue;
		}
		close(ex);

		unlink(path);
		if (!bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) ||
		    *c->sock_path)
			break;
	}

	if (i == UNIX_SOCK_MAX) {
		perror("UNIX socket bind");
		exit(EXIT_FAILURE);
	}

	info("UNIX domain socket bound at %s\n", addr.sun_path);

	listen(fd, 0);

	ev.data.fd = c->fd_tap_listen = fd;
	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, c->fd_tap_listen, &ev);

	info("You can now start qrap:");
	info("    ./qrap 5 kvm ... -net socket,fd=5 -net nic,model=virtio");
	info("or directly qemu, patched with:");
	info("    qemu/0001-net-Allow-also-UNIX-domain-sockets-to-be-used-as-net.patch");
	info("as follows:");
	info("    kvm ... -net socket,connect=%s -net nic,model=virtio",
	     addr.sun_path);
}

/**
 * tap_sock_unix_new() - Handle new connection on listening socket
 * @c:		Execution context
 */
static void tap_sock_unix_new(struct ctx *c)
{
	struct epoll_event ev = { 0 };
	int v = INT_MAX / 2;

	/* Another client is already connected: accept and close right away. */
	if (c->fd_tap != -1) {
		int discard = accept4(c->fd_tap_listen, NULL, NULL,
				      SOCK_NONBLOCK);

		if (discard != -1)
			close(discard);

		return;
	}

	c->fd_tap = accept4(c->fd_tap_listen, NULL, NULL, 0);

	if (!c->low_rmem &&
	    setsockopt(c->fd_tap, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)))
		trace("tap: failed to set SO_RCVBUF to %i", v);

	if (!c->low_wmem &&
	    setsockopt(c->fd_tap, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)))
		trace("tap: failed to set SO_SNDBUF to %i", v);

	ev.data.fd = c->fd_tap;
	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, c->fd_tap, &ev);
}

static int tun_ns_fd = -1;

/**
 * tap_ns_tun() - Get tuntap fd in namespace
 * @c:		Execution context
 *
 * Return: 0
 *
 * #syscalls:pasta ioctl openat
 */
static int tap_ns_tun(void *arg)
{
	struct ifreq ifr = { .ifr_flags = IFF_TAP | IFF_NO_PI };
	int flags = O_RDWR | O_NONBLOCK | O_CLOEXEC;
	struct ctx *c = (struct ctx *)arg;

	strncpy(ifr.ifr_name, c->pasta_ifn, IFNAMSIZ);

	if (ns_enter(c) ||
	    (tun_ns_fd = open("/dev/net/tun", flags)) < 0 ||
	    ioctl(tun_ns_fd, TUNSETIFF, &ifr) ||
	    !(c->pasta_ifi = if_nametoindex(c->pasta_ifn)))
		tun_ns_fd = -1;

	return 0;
}

/**
 * tap_sock_init_tun() - Set up tuntap file descriptor
 * @c:		Execution context
 */
static void tap_sock_tun_init(struct ctx *c)
{
	struct epoll_event ev = { 0 };

	NS_CALL(tap_ns_tun, c);
	if (tun_ns_fd == -1) {
		err("Failed to open tun socket in namespace");
		exit(EXIT_FAILURE);
	}

	pasta_ns_conf(c);

	c->fd_tap = tun_ns_fd;

	ev.data.fd = c->fd_tap;
	ev.events = EPOLLIN | EPOLLRDHUP;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, c->fd_tap, &ev);
}

/**
 * tap_sock_init() - Create and set up AF_UNIX socket or tuntap file descriptor
 * @c:		Execution context
 */
void tap_sock_init(struct ctx *c)
{
	size_t sz = sizeof(pkt_buf);
	int i;

	pool_tap4_storage = PACKET_INIT(pool_tap4, TAP_MSGS, pkt_buf, sz);
	pool_tap6_storage = PACKET_INIT(pool_tap6, TAP_MSGS, pkt_buf, sz);

	for (i = 0; i < TAP_SEQS; i++) {
		tap4_l4[i].p = PACKET_INIT(pool_l4, TAP_SEQS, pkt_buf, sz);
		tap6_l4[i].p = PACKET_INIT(pool_l4, TAP_SEQS, pkt_buf, sz);
	}

	if (c->fd_tap != -1) {
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_tap, NULL);
		close(c->fd_tap);
		c->fd_tap = -1;
	}

	if (c->mode == MODE_PASST) {
		if (c->fd_tap_listen == -1)
			tap_sock_unix_init(c);
	} else {
		tap_sock_tun_init(c);
	}
}

/**
 * tap_handler() - Packet handler for AF_UNIX or tuntap file descriptor
 * @c:		Execution context
 * @fd:		File descriptor where event occurred
 * @events:	epoll events
 * @now:	Current timestamp, can be NULL on EPOLLERR
 */
void tap_handler(struct ctx *c, int fd, uint32_t events,
		 const struct timespec *now)
{
	if (fd == c->fd_tap_listen && events == EPOLLIN) {
		tap_sock_unix_new(c);
		return;
	}

	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))
		goto reinit;

	if ((c->mode == MODE_PASST && tap_handler_passt(c, now)) ||
	    (c->mode == MODE_PASTA && tap_handler_pasta(c, now)))
		goto reinit;

	return;
reinit:
	tap_sock_init(c);
}

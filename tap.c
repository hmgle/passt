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
#include <stdbool.h>
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
#include "log.h"

/* IPv4 (plus ARP) and IPv6 message batches from tap/guest to IP handlers */
static PACKET_POOL_NOINIT(pool_tap4, TAP_MSGS, pkt_buf);
static PACKET_POOL_NOINIT(pool_tap6, TAP_MSGS, pkt_buf);

#define TAP_SEQS		128 /* Different L4 tuples in one batch */

/**
 * tap_send() - Send frame, with qemu socket header if needed
 * @c:		Execution context
 * @data:	Packet buffer
 * @len:	Total L2 packet length
 *
 * Return: return code from send() or write()
 */
int tap_send(const struct ctx *c, const void *data, size_t len)
{
	pcap(data, len);

	if (c->mode == MODE_PASST) {
		int flags = MSG_NOSIGNAL | MSG_DONTWAIT;
		uint32_t vnet_len = htonl(len);

		if (send(c->fd_tap, &vnet_len, 4, flags) < 0)
			return -1;

		return send(c->fd_tap, data, len, flags);
	}

	return write(c->fd_tap, (char *)data, len);
}

/**
 * tap_ip4_daddr() - Normal IPv4 destination address for inbound packets
 * @c:		Execution context
 *
 * Return: IPv4 address, network order
 */
struct in_addr tap_ip4_daddr(const struct ctx *c)
{
	return c->ip4.addr_seen;
}

/**
 * tap_ip6_daddr() - Normal IPv6 destination address for inbound packets
 * @c:		Execution context
 * @src:	Source address
 *
 * Return: pointer to IPv6 address
 */
const struct in6_addr *tap_ip6_daddr(const struct ctx *c,
				     const struct in6_addr *src)
{
	if (IN6_IS_ADDR_LINKLOCAL(src))
		return &c->ip6.addr_ll_seen;
	return &c->ip6.addr_seen;
}

/**
 * tap_push_l2h() - Build an L2 header for an inbound packet
 * @c:		Execution context
 * @buf:	Buffer address at which to generate header
 * @proto:	Ethernet protocol number for L3
 *
 * Return: pointer at which to write the packet's payload
 */
static void *tap_push_l2h(const struct ctx *c, void *buf, uint16_t proto)
{
	struct ethhdr *eh = (struct ethhdr *)buf;

	/* TODO: ARP table lookup */
	memcpy(eh->h_dest, c->mac_guest, ETH_ALEN);
	memcpy(eh->h_source, c->mac, ETH_ALEN);
	eh->h_proto = ntohs(proto);
	return eh + 1;
}

/**
 * tap_push_ip4h() - Build IPv4 header for inbound packet, with checksum
 * @c:		Execution context
 * @src:	IPv4 source address, network order
 * @dst:	IPv4 destination address, network order
 * @len:	L4 payload length
 * @proto:	L4 protocol number
 *
 * Return: pointer at which to write the packet's payload
 */
static void *tap_push_ip4h(char *buf, struct in_addr src, struct in_addr dst,
			   size_t len, uint8_t proto)
{
	struct iphdr *ip4h = (struct iphdr *)buf;

	ip4h->version = 4;
	ip4h->ihl = sizeof(struct iphdr) / 4;
	ip4h->tos = 0;
	ip4h->tot_len = htons(len + sizeof(*ip4h));
	ip4h->id = 0;
	ip4h->frag_off = 0;
	ip4h->ttl = 255;
	ip4h->protocol = proto;
	ip4h->saddr = src.s_addr;
	ip4h->daddr = dst.s_addr;
	csum_ip4_header(ip4h);
	return ip4h + 1;
}

/**
 * tap_udp4_send() - Send UDP over IPv4 packet
 * @c:		Execution context
 * @src:	IPv4 source address
 * @sport:	UDP source port
 * @dst:	IPv4 destination address
 * @dport:	UDP destination port
 * @in:		UDP payload contents (not including UDP header)
 * @len:	UDP payload length (not including UDP header)
 */
void tap_udp4_send(const struct ctx *c, struct in_addr src, in_port_t sport,
		   struct in_addr dst, in_port_t dport,
		   const void *in, size_t len)
{
	size_t udplen = len + sizeof(struct udphdr);
	char buf[USHRT_MAX];
	void *ip4h = tap_push_l2h(c, buf, ETH_P_IP);
	void *uhp = tap_push_ip4h(ip4h, src, dst, udplen, IPPROTO_UDP);
	struct udphdr *uh = (struct udphdr *)uhp;
	char *data = (char *)(uh + 1);

	uh->source = htons(sport);
	uh->dest = htons(dport);
	uh->len = htons(udplen);
	csum_udp4(uh, src, dst, in, len);
	memcpy(data, in, len);

	if (tap_send(c, buf, len + (data - buf)) < 0)
		debug("tap: failed to send %lu bytes (IPv4)", len);
}

/**
 * tap_icmp4_send() - Send ICMPv4 packet
 * @c:		Execution context
 * @src:	IPv4 source address
 * @dst:	IPv4 destination address
 * @in:		ICMP packet, including ICMP header
 * @len:	ICMP packet length, including ICMP header
 */
void tap_icmp4_send(const struct ctx *c, struct in_addr src, struct in_addr dst,
		    void *in, size_t len)
{
	char buf[USHRT_MAX];
	void *ip4h = tap_push_l2h(c, buf, ETH_P_IP);
	char *data = tap_push_ip4h(ip4h, src, dst, len, IPPROTO_ICMP);
	struct icmphdr *icmp4h = (struct icmphdr *)data;

	memcpy(data, in, len);
	csum_icmp4(icmp4h, icmp4h + 1, len - sizeof(*icmp4h));

	if (tap_send(c, buf, len + (data - buf)) < 0)
		debug("tap: failed to send %lu bytes (IPv4)", len);
}

/**
 * tap_push_ip6h() - Build IPv6 header for inbound packet
 * @c:		Execution context
 * @src:	IPv6 source address
 * @dst:	IPv6 destination address
 * @len:	L4 payload length
 * @proto:	L4 protocol number
 * @flow:	IPv6 flow identifier
 *
 * Return: pointer at which to write the packet's payload
 */
static void *tap_push_ip6h(char *buf,
			   const struct in6_addr *src,
			   const struct in6_addr *dst,
			   size_t len, uint8_t proto, uint32_t flow)
{
	struct ipv6hdr *ip6h = (struct ipv6hdr *)buf;

	ip6h->payload_len = htons(len);
	ip6h->priority = 0;
	ip6h->version = 6;
	ip6h->nexthdr = proto;
	ip6h->hop_limit = 255;
	ip6h->saddr = *src;
	ip6h->daddr = *dst;
	ip6h->flow_lbl[0] = (flow >> 16) & 0xf;
	ip6h->flow_lbl[1] = (flow >> 8) & 0xff;
	ip6h->flow_lbl[2] = (flow >> 0) & 0xff;
	return ip6h + 1;
}

/**
 * tap_udp6_send() - Send UDP over IPv6 packet
 * @c:		Execution context
 * @src:	IPv6 source address
 * @sport:	UDP source port
 * @dst:	IPv6 destination address
 * @dport:	UDP destination port
 * @flow:	Flow label
 * @in:		UDP payload contents (not including UDP header)
 * @len:	UDP payload length (not including UDP header)
 */
void tap_udp6_send(const struct ctx *c,
		   const struct in6_addr *src, in_port_t sport,
		   const struct in6_addr *dst, in_port_t dport,
		   uint32_t flow, const void *in, size_t len)
{
	size_t udplen = len + sizeof(struct udphdr);
	char buf[USHRT_MAX];
	void *ip6h = tap_push_l2h(c, buf, ETH_P_IPV6);
	void *uhp = tap_push_ip6h(ip6h, src, dst, udplen, IPPROTO_UDP, flow);
	struct udphdr *uh = (struct udphdr *)uhp;
	char *data = (char *)(uh + 1);

	uh->source = htons(sport);
	uh->dest = htons(dport);
	uh->len = htons(udplen);
	csum_udp6(uh, src, dst, in, len);
	memcpy(data, in, len);

	if (tap_send(c, buf, len + (data - buf)) < 1)
		debug("tap: failed to send %lu bytes (IPv6)", len);
}

/**
 * tap_icmp6_send() - Send ICMPv6 packet
 * @c:		Execution context
 * @src:	IPv6 source address
 * @dst:	IPv6 destination address
 * @in:		ICMP packet, including ICMP header
 * @len:	ICMP packet length, including ICMP header
 */
void tap_icmp6_send(const struct ctx *c,
		    const struct in6_addr *src, const struct in6_addr *dst,
		    void *in, size_t len)
{
	char buf[USHRT_MAX];
	void *ip6h = tap_push_l2h(c, buf, ETH_P_IPV6);
	char *data = tap_push_ip6h(ip6h, src, dst, len, IPPROTO_ICMPV6, 0);
	struct icmp6hdr *icmp6h = (struct icmp6hdr *)data;

	memcpy(data, in, len);
	csum_icmp6(icmp6h, src, dst, icmp6h + 1, len - sizeof(*icmp6h));

	if (tap_send(c, buf, len + (data - buf)) < 1)
		debug("tap: failed to send %lu bytes (IPv6)", len);
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

	struct in_addr saddr;
	struct in_addr daddr;

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
		if (iph) {
			inet_ntop(AF_INET, &iph->saddr, buf4s, sizeof(buf4s));
			inet_ntop(AF_INET, &iph->daddr, buf4d, sizeof(buf4d));
			proto = iph->protocol;
		} else {
			inet_ntop(AF_INET, &seq4->saddr, buf4s, sizeof(buf4s));
			inet_ntop(AF_INET, &seq4->daddr, buf4d, sizeof(buf4d));
			proto = seq4->protocol;
		}
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

	if (!c->ifi4 || !in->count)
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

		if (iph->saddr && c->ip4.addr_seen.s_addr != iph->saddr) {
			c->ip4.addr_seen.s_addr = iph->saddr;
			proto_update_l2_buf(NULL, NULL, &c->ip4.addr_seen);
		}

		l4h = packet_get(in, i, sizeof(*eh) + hlen, l4_len, NULL);
		if (!l4h)
			continue;

		if (iph->protocol == IPPROTO_ICMP) {
			PACKET_POOL_P(pkt, 1, in->buf, sizeof(pkt_buf));

			if (c->no_icmp)
				continue;

			tap_packet_debug(iph, NULL, NULL, 0, NULL, 1);

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
	 seq->saddr.s_addr == iph->saddr && seq->daddr.s_addr == iph->daddr)

#define L4_SET(iph, uh, seq)						\
	do {								\
		seq->protocol		= iph->protocol;		\
		seq->source		= uh->source;			\
		seq->dest		= uh->dest;			\
		seq->saddr.s_addr	= iph->saddr;			\
		seq->daddr.s_addr	= iph->daddr;			\
	} while (0)

		if (seq && L4_MATCH(iph, uh, seq) && seq->p.count < TAP_SEQS)
			goto append;

		if (seq_count == TAP_SEQS)
			break;	/* Resume after flushing if i < in->count */

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
	}

	for (j = 0, seq = tap4_l4; j < seq_count; j++, seq++) {
		struct pool *p = (struct pool *)&seq->p;
		struct in_addr *da = &seq->daddr;
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

	if (!c->ifi6 || !in->count)
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
			c->ip6.addr_ll_seen = *saddr;

			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_seen)) {
				c->ip6.addr_seen = *saddr;
			}
		} else {
			c->ip6.addr_seen = *saddr;
		}

		if (proto == IPPROTO_ICMPV6) {
			PACKET_POOL_P(pkt, 1, in->buf, sizeof(pkt_buf));

			if (c->no_icmp)
				continue;

			if (l4_len < sizeof(struct icmp6hdr))
				continue;

			if (ndp(c, (struct icmp6hdr *)l4h, saddr))
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

		*saddr = c->ip6.addr;

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

		if (seq_count == TAP_SEQS)
			break;	/* Resume after flushing if i < in->count */

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
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct epoll_event ev = { 0 };
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	int i;

	if (fd < 0) {
		err("UNIX socket: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* In passt mode, we don't know the guest's MAC until it sends
	 * us packets.  Use the broadcast address so our first packets
	 * will reach it.
	 */
	memset(&c->mac_guest, 0xff, sizeof(c->mac_guest));

	for (i = 1; i < UNIX_SOCK_MAX; i++) {
		char *path = addr.sun_path;
		int ex, ret;

		if (*c->sock_path)
			memcpy(path, c->sock_path, UNIX_PATH_MAX);
		else
			snprintf(path, UNIX_PATH_MAX - 1, UNIX_SOCK_PATH, i);

		ex = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if (ex < 0) {
			err("UNIX domain socket check: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		ret = connect(ex, (const struct sockaddr *)&addr, sizeof(addr));
		if (!ret || (errno != ENOENT && errno != ECONNREFUSED &&
			     errno != EACCES)) {
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
		err("UNIX socket bind: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	info("UNIX domain socket bound at %s\n", addr.sun_path);

	listen(fd, 0);

	ev.data.fd = c->fd_tap_listen = fd;
	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, c->fd_tap_listen, &ev);

	info("You can now start qemu (>= 7.2, with commit 13c6be96618c):");
	info("    kvm ... -device virtio-net-pci,netdev=s -netdev stream,id=s,server=off,addr.type=unix,addr.path=%s",
	     addr.sun_path);
	info("or qrap, for earlier qemu versions:");
	info("    ./qrap 5 kvm ... -net socket,fd=5 -net nic,model=virtio");
}

/**
 * tap_sock_unix_new() - Handle new connection on listening socket
 * @c:		Execution context
 */
static void tap_sock_unix_new(struct ctx *c)
{
	struct epoll_event ev = { 0 };
	int v = INT_MAX / 2;
	struct ucred ucred;
	socklen_t len;

	len = sizeof(ucred);

	/* Another client is already connected: accept and close right away. */
	if (c->fd_tap != -1) {
		int discard = accept4(c->fd_tap_listen, NULL, NULL,
				      SOCK_NONBLOCK);

		if (discard == -1)
			return;

		if (!getsockopt(discard, SOL_SOCKET, SO_PEERCRED, &ucred, &len))
			info("discarding connection from PID %i", ucred.pid);

		close(discard);

		return;
	}

	c->fd_tap = accept4(c->fd_tap_listen, NULL, NULL, 0);

	if (!getsockopt(c->fd_tap, SOL_SOCKET, SO_PEERCRED, &ucred, &len))
		info("accepted connection from PID %i", ucred.pid);

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

	memcpy(ifr.ifr_name, c->pasta_ifn, IFNAMSIZ);

	if (ns_enter(c) ||
	    (tun_ns_fd = open("/dev/net/tun", flags)) < 0 ||
	    ioctl(tun_ns_fd, TUNSETIFF, &ifr) ||
	    !(c->pasta_ifi = if_nametoindex(c->pasta_ifn))) {
		if (tun_ns_fd != -1)
			close(tun_ns_fd);
		tun_ns_fd = -1;
	}

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
	if (c->one_off) {
		info("Client closed connection, exiting");
		exit(EXIT_SUCCESS);
	}

	tap_sock_init(c);
}

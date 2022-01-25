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
 * #syscalls recvfrom sendto
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

/* IPv4 (plus ARP) and IPv6 message batches from tap/guest to IP handlers */
static struct tap_msg seq4[TAP_MSGS];
static struct tap_msg seq6[TAP_MSGS];

/**
 * tap_send() - Send frame, with qemu socket header if needed
 * @c:		Execution context
 * @data:	Packet buffer
 * @len:	Total L2 packet length
 * @vnet_pre:	Buffer has four-byte headroom
 *
 * Return: return code from send() or write()
 */
int tap_send(struct ctx *c, void *data, size_t len, int vnet_pre)
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

			send(c->fd_tap, &vnet_len, 4, flags);
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
void tap_ip_send(struct ctx *c, struct in6_addr *src, uint8_t proto,
		 char *in, size_t len, uint32_t flow)
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
		iph->check = csum_unaligned(iph, iph->ihl * 4, 0);

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

		tap_send(c, buf, len + sizeof(*iph) + sizeof(*eh), 1);
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

		tap_send(c, buf, len + sizeof(*ip6h) + sizeof(*eh), 1);
	}
}

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
static struct tap_l4_seq4 {
	uint16_t msgs;
	uint8_t protocol;

	uint16_t source;
	uint16_t dest;

	uint32_t saddr;
	uint32_t daddr;

	struct tap_l4_msg msg[UIO_MAXIOV];
} l4_seq4[UIO_MAXIOV /* Arbitrary: TAP_MSGS in theory, so limit in users */];

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
static struct tap_l4_seq6 {
	uint16_t msgs;
	uint8_t protocol;

	uint16_t source;
	uint16_t dest;

	struct in6_addr saddr;
	struct in6_addr daddr;

	struct tap_l4_msg msg[UIO_MAXIOV];
} l4_seq6[UIO_MAXIOV /* Arbitrary: TAP_MSGS in theory, so limit in users */];

/**
 * tap_packet_debug() - Print debug message for packet(s) from guest/tap
 * @iph:	IPv4 header, can be NULL
 * @ip6h:	IPv6 header, can be NULL
 * @seq4:	Pointer to @struct tap_l4_seq4, can be NULL
 * @proto6:	IPv6 protocol, for IPv6
 * @seq6:	Pointer to @struct tap_l4_seq6, can be NULL
 * @count:	Count of packets in this sequence
 */
static void tap_packet_debug(struct iphdr *iph, struct ipv6hdr *ip6h,
			     struct tap_l4_seq4 *seq4, uint8_t proto6,
			     struct tap_l4_seq6 *seq6, int count)
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
		debug("protocol %i from tap: %s:%i -> %s:%i (%i packet%s)",
		      proto, seq4 ? buf4s : buf6s,
		      ntohs(seq4 ? seq4->source : seq6->source),
		      seq4 ? buf4d : buf6d,
		      ntohs(seq4 ? seq4->dest : seq6->dest),
		      count, count == 1 ? "" : "s");
	} else {
		debug("protocol %i from tap: %s -> %s (%i packet%s)",
		      proto, iph ? buf4s : buf6s, iph ? buf4d : buf6d,
		      count, count == 1 ? "" : "s");
	}
}

/**
 * tap4_handler() - IPv4 and ARP packet handler for tap file descriptor
 * @c:		Execution context
 * @msg:	Array of messages with IPv4 or ARP protocol
 * @count:	Count of messages
 * @now:	Current timestamp
 *
 * Return: count of packets consumed by handlers
 */
static int tap4_handler(struct ctx *c, struct tap_msg *msg, size_t count,
			struct timespec *now)
{
	unsigned int i, j, seq_count;
	struct tap_l4_msg *l4_msg;
	struct tap_l4_seq4 *seq;
	size_t len, l4_len;
	struct ethhdr *eh;
	struct iphdr *iph;
	struct udphdr *uh;
	char *l4h;

	if (!c->v4)
		return count;

	i = 0;
resume:
	for (seq_count = 0, seq = NULL; i < count; i++) {
		eh = (struct ethhdr *)(pkt_buf + msg[i].pkt_buf_offset);
		len = msg[i].len;

		if (len < sizeof(*eh))
			continue;

		if (ntohs(eh->h_proto) == ETH_P_ARP && arp(c, eh, len))
			continue;

		if (len < sizeof(*eh) + sizeof(*iph))
			continue;

		iph = (struct iphdr *)(eh + 1);
		if ((iph->ihl * 4) + sizeof(*eh) > len)
			continue;
		if (iph->ihl * 4 < (int)sizeof(*iph))
			continue;

		if (iph->saddr && c->addr4_seen != iph->saddr) {
			c->addr4_seen = iph->saddr;
			proto_update_l2_buf(NULL, NULL, &c->addr4_seen);
		}

		l4h = (char *)iph + iph->ihl * 4;
		l4_len = len - ((intptr_t)l4h - (intptr_t)eh);

		if (iph->protocol == IPPROTO_ICMP) {
			struct tap_l4_msg icmp_msg = { l4h - pkt_buf,
						       l4_len };

			if (l4_len < sizeof(struct icmphdr))
				continue;

			tap_packet_debug(iph, NULL, NULL, 0, NULL, 1);
			if (!c->no_icmp) {
				icmp_tap_handler(c, AF_INET, &iph->daddr,
						 &icmp_msg, 1, now);
			}
			continue;
		}

		if (l4_len < sizeof(*uh))
			continue;

		uh = (struct udphdr *)l4h;

		if (iph->protocol == IPPROTO_UDP && dhcp(c, eh, len))
			continue;

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

		if (seq && L4_MATCH(iph, uh, seq) && seq->msgs < UIO_MAXIOV)
			goto append;

		for (seq = l4_seq4 + seq_count - 1; seq >= l4_seq4; seq--) {
			if (L4_MATCH(iph, uh, seq)) {
				if (seq->msgs >= UIO_MAXIOV)
					seq = NULL;
				break;
			}
		}

		if (!seq || seq < l4_seq4) {
			seq = l4_seq4 + seq_count++;
			L4_SET(iph, uh, seq);
			seq->msgs = 0;
		}

#undef L4_MATCH
#undef L4_SET

append:
		l4_msg = &seq->msg[seq->msgs++];

		l4_msg->pkt_buf_offset = l4h - pkt_buf;
		l4_msg->l4_len = l4_len;

		if (seq_count == UIO_MAXIOV)
			break;	/* Resume after flushing if i < count */
	}

	for (j = 0, seq = l4_seq4; j < seq_count; j++, seq++) {
		int n = seq->msgs;

		l4_msg = seq->msg;

		tap_packet_debug(NULL, NULL, seq, 0, NULL, n);

		if (seq->protocol == IPPROTO_TCP) {
			if (c->no_tcp)
				continue;
			while ((n -= tcp_tap_handler(c, AF_INET, &seq->daddr,
						     l4_msg, n, now)));
		} else if (seq->protocol == IPPROTO_UDP) {
			if (c->no_udp)
				continue;
			while ((n -= udp_tap_handler(c, AF_INET, &seq->daddr,
						     l4_msg, n, now)));
		}
	}

	if (i < count)
		goto resume;

	return count;
}

/**
 * tap6_handler() - IPv6 packet handler for tap file descriptor
 * @c:		Execution context
 * @msg:	Array of messages with IPv6 protocol
 * @count:	Count of messages
 * @now:	Current timestamp
 *
 * Return: count of packets consumed by handlers
 */
static int tap6_handler(struct ctx *c, struct tap_msg *msg, size_t count,
			struct timespec *now)
{
	unsigned int i, j, seq_count = 0;
	struct tap_l4_msg *l4_msg;
	struct tap_l4_seq6 *seq;
	struct ipv6hdr *ip6h;
	size_t len, l4_len;
	struct ethhdr *eh;
	struct udphdr *uh;
	uint8_t proto;
	char *l4h;

	if (!c->v6)
		return count;

	i = 0;
resume:
	for (seq_count = 0, seq = NULL; i < count; i++) {
		eh = (struct ethhdr *)(pkt_buf + msg[i].pkt_buf_offset);
		len = msg[i].len;

		if (len < sizeof(*eh))
			continue;

		if (len < sizeof(*eh) + sizeof(*ip6h))
			return 1;

		ip6h = (struct ipv6hdr *)(eh + 1);

		if (IN6_IS_ADDR_LINKLOCAL(&ip6h->saddr)) {
			c->addr6_ll_seen = ip6h->saddr;

			if (IN6_IS_ADDR_UNSPECIFIED(&c->addr6_seen)) {
				c->addr6_seen = ip6h->saddr;
			}
		} else {
			c->addr6_seen = ip6h->saddr;
		}

		if (ntohs(ip6h->payload_len) >
		    len - sizeof(*eh) - sizeof(*ip6h))
			continue;

		if (!(l4h = ipv6_l4hdr(ip6h, &proto)))
			continue;

		l4_len = len - ((intptr_t)l4h - (intptr_t)eh);

		if (proto == IPPROTO_ICMPV6) {
			struct tap_l4_msg icmpv6_msg = { l4h - pkt_buf,
						         l4_len };

			if (l4_len < sizeof(struct icmp6hdr))
				continue;

			if (ndp(c, eh, len))
				continue;

			tap_packet_debug(NULL, ip6h, NULL, proto, NULL, 1);
			if (!c->no_icmp) {
				icmp_tap_handler(c, AF_INET6, &ip6h->daddr,
						 &icmpv6_msg, 1, now);
			}
			continue;
		}

		if (l4_len < sizeof(*uh))
			continue;

		uh = (struct udphdr *)l4h;

		if (proto == IPPROTO_UDP && dhcpv6(c, eh, len))
			continue;

		ip6h->saddr = c->addr6;

		if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
			tap_packet_debug(NULL, ip6h, NULL, proto, NULL, 1);
			continue;
		}

#define L4_MATCH(ip6h, proto, uh, seq)					\
	(seq->protocol == proto         &&				\
	 seq->source   == uh->source    && seq->dest  == uh->dest &&	\
	 !memcmp(&seq->saddr, &ip6h->saddr, sizeof(seq->saddr))   &&	\
	 !memcmp(&seq->daddr, &ip6h->daddr, sizeof(seq->daddr)))

#define L4_SET(ip6h, proto, uh, seq)					\
	do {								\
		seq->protocol	= proto;				\
		seq->source	= uh->source;				\
		seq->dest	= uh->dest;				\
		seq->saddr	= ip6h->saddr;				\
		seq->daddr	= ip6h->daddr;				\
	} while (0)

		if (seq && L4_MATCH(ip6h, proto, uh, seq) &&
		    seq->msgs < UIO_MAXIOV)
			goto append;

		for (seq = l4_seq6 + seq_count - 1; seq >= l4_seq6; seq--) {
			if (L4_MATCH(ip6h, proto, uh, seq)) {
				if (seq->msgs >= UIO_MAXIOV)
					seq = NULL;
				break;
			}
		}

		if (!seq || seq < l4_seq6) {
			seq = l4_seq6 + seq_count++;
			L4_SET(ip6h, proto, uh, seq);
			seq->msgs = 0;
		}

#undef L4_MATCH
#undef L4_SET

append:
		l4_msg = &seq->msg[seq->msgs++];

		l4_msg->pkt_buf_offset = l4h - pkt_buf;
		l4_msg->l4_len = l4_len;

		if (seq_count == UIO_MAXIOV)
			break;	/* Resume after flushing if i < count */
	}

	for (j = 0, seq = l4_seq6; j < seq_count; j++, seq++) {
		int n = seq->msgs;

		l4_msg = seq->msg;

		tap_packet_debug(NULL, NULL, NULL, seq->protocol, seq, n);

		if (seq->protocol == IPPROTO_TCP) {
			if (c->no_tcp)
				continue;
			while ((n -= tcp_tap_handler(c, AF_INET6, &seq->daddr,
						     l4_msg, n, now)));
		} else if (seq->protocol == IPPROTO_UDP) {
			if (c->no_udp)
				continue;
			while ((n -= udp_tap_handler(c, AF_INET6, &seq->daddr,
						     l4_msg, n, now)));
		}
	}

	if (i < count)
		goto resume;

	return count;
}

/**
 * tap_handler_passt() - Packet handler for AF_UNIX file descriptor
 * @c:		Execution context
 * @now:	Current timestamp
 *
 * Return: -ECONNRESET on receive error, 0 otherwise
 */
static int tap_handler_passt(struct ctx *c, struct timespec *now)
{
	int seq4_i, seq6_i;
	struct ethhdr *eh;
	ssize_t n, rem;
	char *p;

redo:
	p = pkt_buf;
	seq4_i = seq6_i = rem = 0;

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
		if (len < (ssize_t)sizeof(*eh) || len > ETH_MAX_MTU)
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
			seq4[seq4_i].pkt_buf_offset = p - pkt_buf;
			seq4[seq4_i++].len = len;
			break;
		case ETH_P_IPV6:
			seq6[seq6_i].pkt_buf_offset = p - pkt_buf;
			seq6[seq6_i++].len = len;
			break;
		default:
			break;
		}

next:
		p += len;
		n -= len;
	}

	if (seq4_i)
		tap4_handler(c, seq4, seq4_i, now);

	if (seq6_i)
		tap6_handler(c, seq6, seq6_i, now);

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
static int tap_handler_pasta(struct ctx *c, struct timespec *now)
{
	ssize_t n = 0, len;
	int ret, seq4_i = 0, seq6_i = 0;

restart:
	while ((len = read(c->fd_tap, pkt_buf + n, TAP_BUF_BYTES - n)) > 0) {
		struct ethhdr *eh = (struct ethhdr *)(pkt_buf + n);

		if (len < (ssize_t)sizeof(*eh) || len > ETH_MAX_MTU) {
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
			seq4[seq4_i].pkt_buf_offset = n;
			seq4[seq4_i++].len = len;
			break;
		case ETH_P_IPV6:
			seq6[seq6_i].pkt_buf_offset = n;
			seq6[seq6_i++].len = len;
			break;
		default:
			break;
		}

		n += len;
	}

	if (len < 0 && errno == EINTR)
		goto restart;

	ret = errno;

	if (seq4_i)
		tap4_handler(c, seq4, seq4_i, now);

	if (seq6_i)
		tap6_handler(c, seq6, seq6_i, now);

	if (len > 0 || ret == EAGAIN)
		return 0;

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_tap, NULL);
	close(c->fd_tap);

	return -ECONNRESET;
}

/**
 * tap_sock_init_unix() - Create and bind AF_UNIX socket, wait for connection
 * @c:		Execution context
 *
 * #syscalls:passt unlink
 */
static void tap_sock_init_unix(struct ctx *c)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0), ex;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	int i, ret, v = INT_MAX / 2;

	if (c->fd_tap_listen)
		close(c->fd_tap_listen);

	if (fd < 0) {
		perror("UNIX socket");
		exit(EXIT_FAILURE);
	}
	c->fd_tap_listen = fd;

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
#ifdef PASST_LEGACY_NO_OPTIONS
	/*
	 * syscalls:passt chmod
	 */
	chmod(addr.sun_path,
	      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#endif

	pcap_init(c, i);

	listen(fd, 0);

	info("You can now start qrap:");
	info("    ./qrap 5 kvm ... -net socket,fd=5 -net nic,model=virtio");
	info("or directly qemu, patched with:");
	info("    qemu/0001-net-Allow-also-UNIX-domain-sockets-to-be-used-as-net.patch");
	info("as follows:");
	info("    kvm ... -net socket,connect=%s -net nic,model=virtio",
	     addr.sun_path);

	c->fd_tap = accept(fd, NULL, NULL);

	if (!c->low_rmem)
		setsockopt(c->fd_tap, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v));

	if (!c->low_wmem)
		setsockopt(c->fd_tap, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v));
}

static int tun_ns_fd = -1;

/**
 * tap_ns_tun() - Get tuntap fd in namespace
 * @c:		Execution context
 *
 * Return: 0
 *
 * #syscalls:pasta ioctl
 */
static int tap_ns_tun(void *arg)
{
	struct ifreq ifr = { .ifr_flags = IFF_TAP | IFF_NO_PI };
	struct ctx *c = (struct ctx *)arg;

	strncpy(ifr.ifr_name, c->pasta_ifn, IFNAMSIZ);

	if (ns_enter(c) ||
	    (tun_ns_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0 ||
	    ioctl(tun_ns_fd, TUNSETIFF, &ifr) ||
	    !(c->pasta_ifi = if_nametoindex(c->pasta_ifn)))
		tun_ns_fd = -1;

	return 0;
}

/**
 * tap_sock_init_tun() - Set up tuntap file descriptor
 * @c:		Execution context
 */
static void tap_sock_init_tun(struct ctx *c)
{
	NS_CALL(tap_ns_tun, c);
	if (tun_ns_fd == -1) {
		err("Failed to open tun socket in namespace");
		exit(EXIT_FAILURE);
	}

	pasta_ns_conf(c);

	pcap_init(c, c->pasta_netns_fd);

	c->fd_tap = tun_ns_fd;
}

/**
 * tap_sock_init() - Create and set up AF_UNIX socket or tuntap file descriptor
 * @c:		Execution context
 */
void tap_sock_init(struct ctx *c)
{
	struct epoll_event ev = { 0 };

	if (c->fd_tap) {
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_tap, NULL);
		close(c->fd_tap);
	}

	if (c->mode == MODE_PASST) {
		tap_sock_init_unix(c);
		ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
	} else {
		tap_sock_init_tun(c);
		ev.events = EPOLLIN | EPOLLRDHUP;
	}

	ev.data.fd = c->fd_tap;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, c->fd_tap, &ev);
}

/**
 * tap_handler() - Packet handler for AF_UNIX or tuntap file descriptor
 * @c:		Execution context
 * @events:	epoll events
 * @now:	Current timestamp
 */
void tap_handler(struct ctx *c, uint32_t events, struct timespec *now)
{
	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))
		goto fail;

	if ((c->mode == MODE_PASST && tap_handler_passt(c, now)) ||
	    (c->mode == MODE_PASTA && tap_handler_pasta(c, now)))
		goto fail;

	return;
fail:
	tap_sock_init(c);
}

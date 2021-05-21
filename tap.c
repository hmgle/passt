// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *
 * tap.c - Functions to communicate with guest-facing tap interface
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 */

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "passt.h"
#include "util.h"
#include "pcap.h"

/**
 * tap_send() - Send frame and qemu socket header with indication of length
 * @fd:		tap file descriptor
 * @len:	Total L2 packet length
 * @flags:	Flags for send(), if any
 *
 * Return: return code from send()
 */
int tap_send(int fd, void *data, size_t len, int flags)
{
	uint32_t vnet_len = htonl(len);
	send(fd, &vnet_len, 4, MSG_DONTWAIT | MSG_NOSIGNAL);

	pcap(data, len);

	return send(fd, data, len, flags | MSG_DONTWAIT | MSG_NOSIGNAL);
}

/**
 * tap_ip_send() - Send IP packet, with L2 headers, calculating L3/L4 checksums
 * @c:		Execution context
 * @src:	IPv6 source address, IPv4-mapped for IPv4 sources
 * @proto:	L4 protocol number
 * @in:		Payload
 * @len:	L4 payload length
 */
void tap_ip_send(struct ctx *c, struct in6_addr *src, uint8_t proto,
		 char *in, size_t len)
{
	char pkt[USHRT_MAX];
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
		iph->check = csum_ip4(iph, iph->ihl * 4);

		memcpy(data, in, len);

		if (iph->protocol == IPPROTO_TCP) {
			csum_tcp4(iph);
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *uh = (struct udphdr *)(iph + 1);

			uh->check = 0;
		}

		tap_send(c->fd_unix, pkt, len + sizeof(*iph) + sizeof(*eh), 0);
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
			th->check = csum_ip4(ip6h, len + sizeof(*ip6h));
		} else if (proto == IPPROTO_UDP) {
			struct udphdr *uh = (struct udphdr *)(ip6h + 1);

			uh->check = 0;
			uh->check = csum_ip4(ip6h, len + sizeof(*ip6h));
		} else if (proto == IPPROTO_ICMPV6) {
			struct icmp6hdr *ih = (struct icmp6hdr *)(ip6h + 1);

			ih->icmp6_cksum = 0;
			ih->icmp6_cksum = csum_ip4(ip6h, len + sizeof(*ip6h));
		}
		ip6h->version = 6;
		ip6h->nexthdr = proto;
		ip6h->hop_limit = 255;

		tap_send(c->fd_unix, pkt, len + sizeof(*ip6h) + sizeof(*eh), 0);
	}
}

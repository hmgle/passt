// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * ndp.c - NDP support for PASST
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <net/if.h>
#include <net/if_arp.h>

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "tap.h"

#define RS	133
#define RA	134
#define NS	135
#define NA	136

/**
 * ndp() - Check for NDP solicitations, reply as needed
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @eh:		Packet buffer, Ethernet header
 *
 * Return: 0 if not handled here, 1 if handled, -1 on failure
 */
int ndp(struct ctx *c, struct ethhdr *eh, size_t len)
{
	struct ethhdr *ehr;
	struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1), *ip6hr;
	struct icmp6hdr *ih, *ihr;
	char buf[BUFSIZ] = { 0 };
	uint8_t proto, *p;

	if (len < sizeof(*ehr) + sizeof(*ip6h) + sizeof(ih))
		return 0;

	ih = (struct icmp6hdr *)ipv6_l4hdr(ip6h, &proto);
	if (!ih)
		return -1;

	if (proto != IPPROTO_ICMPV6 ||
	    ih->icmp6_type < RS || ih->icmp6_type > NA)
		return 0;

	ehr = (struct ethhdr *)buf;
	ip6hr = (struct ipv6hdr *)(ehr + 1);
	ihr = (struct icmp6hdr *)(ip6hr + 1);

	if (ih->icmp6_type == NS) {
		if (len < sizeof(*ehr) + sizeof(*ip6h) + sizeof(ih) +
			  sizeof(struct in6_addr))
			return -1;

		info("NDP: received NS, sending NA");
		ihr->icmp6_type = NA;
		ihr->icmp6_code = 0;
		ihr->icmp6_router = 1;
		ihr->icmp6_solicited = 1;
		ihr->icmp6_override = 1;

		p = (unsigned char *)(ihr + 1);
		memcpy(p, ih + 1, sizeof(struct in6_addr)); /* target address */
		p += 16;
		*p++ = 2;				    /* target ll */
		*p++ = 1;				    /* length */
		memcpy(p, c->mac, ETH_ALEN);
		p += 6;
	} else if (ih->icmp6_type == RS) {
		size_t len = 0;
		int i, n;

		info("NDP: received RS, sending RA");
		ihr->icmp6_type = RA;
		ihr->icmp6_code = 0;
		ihr->icmp6_rt_lifetime = htons(3600);
		ihr->icmp6_addrconf_managed = 1;

		p = (unsigned char *)(ihr + 1);
		p += 8;				/* reachable, retrans time */
		*p++ = 3;			/* prefix */
		*p++ = 4;			/* length */
		*p++ = 64;			/* prefix length */
		*p++ = 0xc0;			/* prefix flags: L, A */
		*(uint32_t *)p = htonl(3600);	/* lifetime */
		p += 4;
		*(uint32_t *)p = htonl(3600);	/* preferred lifetime */
		p += 8;
		memcpy(p, &c->addr6, 8);	/* prefix */
		p += 16;

		for (n = 0; !IN6_IS_ADDR_UNSPECIFIED(&c->dns6[n]); n++);
		if (n) {
			*p++ = 25;			/* RDNSS */
			*p++ = 1 + 2 * n;		/* length */
			p += 2;				/* reserved */
			*(uint32_t *)p = htonl(60);	/* lifetime */
			p += 4;

			for (i = 0; i < n; i++) {
				memcpy(p, &c->dns6[i], 16);	/* address */
				p += 16;
			}
		}

		for (n = 0; *c->dns_search[n].n; n++)
			len += strlen(c->dns_search[n].n) + 2;
		if (len) {
			*p++ = 31;			/* DNSSL */
			*p++ = (len + 8 - 1) / 8 + 1;	/* length */
			p += 2;				/* reserved */
			*(uint32_t *)p = htonl(60);	/* lifetime */
			p += 4;

			for (i = 0; i < n; i++) {
				char *dot;

				*(p++) = '.';

				strncpy((char *)p, c->dns_search[i].n,
					sizeof(buf) -
					((intptr_t)p - (intptr_t)buf));
				for (dot = (char *)p - 1; *dot; dot++) {
					if (*dot == '.')
						*dot = strcspn(dot + 1, ".");
				}
				p += strlen(c->dns_search[i].n);
				*(p++) = 0;
			}

			memset(p, 0, 8 - len % 8);	/* padding */
			p += 8 - len % 8;
		}

		*p++ = 1;			/* source ll */
		*p++ = 1;			/* length */
		memcpy(p, c->mac, ETH_ALEN);
		p += 6;
	} else {
		return 1;
	}

	len = (uintptr_t)p - (uintptr_t)ihr - sizeof(*ihr);

	if (IN6_IS_ADDR_LINKLOCAL(&ip6h->saddr))
		c->addr6_ll_seen = ip6h->saddr;
	else
		c->addr6_seen = ip6h->saddr;

	ip6hr->daddr = ip6h->saddr;
	ip6hr->saddr = c->gw6;
	ip6hr->payload_len = htons(sizeof(*ihr) + len);
	ip6hr->hop_limit = IPPROTO_ICMPV6;
	ihr->icmp6_cksum = 0;
	ihr->icmp6_cksum = csum_unaligned(ip6hr, sizeof(*ip6hr) +
						 sizeof(*ihr) + len, 0);

	ip6hr->version = 6;
	ip6hr->nexthdr = IPPROTO_ICMPV6;
	ip6hr->hop_limit = 255;

	len += sizeof(*ehr) + sizeof(*ip6hr) + sizeof(*ihr);
	memcpy(ehr->h_dest, eh->h_source, ETH_ALEN);
	memcpy(ehr->h_source, c->mac, ETH_ALEN);
	ehr->h_proto = htons(ETH_P_IPV6);

	if (tap_send(c, ehr, len, 0) < 0)
		perror("NDP: send");

	return 1;
}

// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * arp.c - ARP implementation
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <linux/ipv6.h>

#include "util.h"
#include "arp.h"
#include "dhcp.h"
#include "passt.h"
#include "tap.h"

/**
 * arp() - Check if this is an ARP message, reply as needed
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @eh:		Packet buffer, Ethernet header
 *
 * Return: 0 if it's not an ARP message, 1 if handled, -1 on failure
 */
int arp(struct ctx *c, struct ethhdr *eh, size_t len)
{
	struct arphdr *ah = (struct arphdr *)(eh + 1);
	struct arpmsg *am = (struct arpmsg *)(ah + 1);
	unsigned char swap[4];

	if (eh->h_proto != htons(ETH_P_ARP))
		return 0;

	if (len < sizeof(*eh) + sizeof(*ah) + sizeof(*am))
		return -1;

	if (ah->ar_hrd != htons(ARPHRD_ETHER) ||
	    ah->ar_pro != htons(ETH_P_IP) ||
	    ah->ar_hln != ETH_ALEN || ah->ar_pln != 4 ||
	    ah->ar_op != htons(ARPOP_REQUEST))
		return 1;

	/* Discard announcements (but not 0.0.0.0 "probes"): we might have the
	 * same IP address, hide that.
	 */
	if (*((uint32_t *)&am->sip) && !memcmp(am->sip, am->tip, 4))
		return 1;

	/* Don't resolve our own address, either. */
	if (!memcmp(am->tip, &c->addr4, 4))
		return 1;

	ah->ar_op = htons(ARPOP_REPLY);
	memcpy(am->tha, am->sha, ETH_ALEN);
	memcpy(am->sha, c->mac, ETH_ALEN);

	memcpy(swap, am->tip, 4);
	memcpy(am->tip, am->sip, 4);
	memcpy(am->sip, swap, 4);

	len = sizeof(*eh) + sizeof(*ah) + sizeof(*am);
	memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
	memcpy(eh->h_source, c->mac, ETH_ALEN);

	if (tap_send(c, eh, len, 0) < 0)
		perror("ARP: send");

	return 1;
}

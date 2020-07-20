/* MERD - MacVTap Egress and Routing Daemon
 *
 * arp.c - ARP implementation
 *
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * License: GPLv2
 *
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#include "merd.h"
#include "dhcp.h"
#include "util.h"

/**
 * struct arpmsg - 802.2 ARP IPv4 payload
 * @sha:	Sender hardware address
 * @sip:	Sender IP address
 * @tha:	Target hardware address
 * @tip:	Target IP address
 */
struct arpmsg {
	unsigned char sha[ETH_ALEN];
	unsigned char sip[4];
	unsigned char tha[ETH_ALEN];
	unsigned char tip[4];
} __attribute__((__packed__));

/**
 * dhcp() - Check if this is an ARP message, reply as needed
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @eh:		Packet buffer, Ethernet header
 *
 * Return: 0 if it's not an ARP message, 1 if handled, -1 on failure
 */
int arp(struct ctx *c, unsigned len, struct ethhdr *eh)
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

	ah->ar_op = htons(ARPOP_REPLY);
	memcpy(am->tha, am->sha, ETH_ALEN);
	memcpy(am->sha, c->mac, ETH_ALEN);

	memcpy(swap, am->tip, 4);
	memcpy(am->tip, am->sip, 4);
	memcpy(am->sip, swap, 4);

	len = sizeof(*eh) + sizeof(*ah) + sizeof(*am);
	memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
	memcpy(eh->h_source, c->mac, ETH_ALEN);

	if (send(c->fd_unix, eh, len, 0) < 0)
		perror("ARP: send");

	return 1;
}

// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * dhcp.c - Minimalistic DHCP server for PASST
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "dhcp.h"
#include "tap.h"

/**
 * struct opt - DHCP option
 * @sent:	Convenience flag, set while filling replies
 * @slen:	Length of option defined for server
 * @s:		Option payload from server
 * @clen:	Length of option received from client
 * @c:		Option payload from client
 */
struct opt {
	int sent;
	int slen;
	unsigned char s[255];
	int clen;
	unsigned char c[255];
};

static struct opt opts[255];

#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8
#define DHCPFORCERENEW	9

/**
 * dhcp_init() - Initialise DHCP options
 */
void dhcp_init(void)
{
	opts[1]  = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Mask */
	opts[3]  = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Router */
	opts[51] = (struct opt) { 0, 4, {  0xff,
					   0xff,
					   0xff,
					   0xff }, 0, { 0 }, };	/* Lease time */
	opts[53] = (struct opt) { 0, 1, {     0 }, 0, { 0 }, };	/* Type */
	opts[54] = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Server ID */
}

/**
 * struct msg - BOOTP/DHCP message
 * @op:		BOOTP message type
 * @htype:	Hardware address type
 * @hlen:	Hardware address length
 * @hops:	DHCP relay hops
 * @xid:	Transaction ID randomly chosen by client
 * @secs:	Seconds elapsed since beginning of acquisition or renewal
 * @flags:	DHCP message flags
 * @ciaddr:	Client IP address in BOUND, RENEW, REBINDING
 * @yiaddr:	IP address being offered or assigned
 * @siaddr:	Next server to use in bootstrap
 * @giaddr:	Relay agent IP address
 * @chaddr:	Client hardware address
 * @sname:	Server host name
 * @file:	Boot file name
 * @magic:	Magic cookie prefix before options
 * @o:		Options
 */
struct msg {
	uint8_t op;
#define BOOTREQUEST	1
#define BOOTREPLY	2
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic;
	uint8_t o[308];
} __attribute__((__packed__));

/**
 * fill_one() - Fill a single option in message
 * @m:		Message to fill
 * @o:		Option number
 * @offset:	Current offset within options field, updated on insertion
 */
static void fill_one(struct msg *m, int o, int *offset)
{
	m->o[*offset] = o;
	m->o[*offset + 1] = opts[o].slen;
	memcpy(&m->o[*offset + 2], opts[o].s, opts[o].slen);

	opts[o].sent = 1;
	*offset += 2 + opts[o].slen;
}

/**
 * fill() - Fill options in message
 * @m:		Message to fill
 *
 * Return: current size of options field
 */
static int fill(struct msg *m)
{
	int i, o, offset = 0;

	m->op = BOOTREPLY;
	m->secs = 0;

	for (o = 0; o < 255; o++)
		opts[o].sent = 0;

	for (i = 0; i < opts[55].clen; i++) {
		o = opts[55].c[i];
		if (opts[o].slen)
			fill_one(m, o, &offset);
	}

	for (o = 0; o < 255; o++) {
		if (opts[o].slen && !opts[o].sent)
			fill_one(m, o, &offset);
	}

	m->o[offset++] = 255;
	m->o[offset++] = 0;

	if (offset < 62 /* RFC 951 */) {
		memset(&m->o[offset], 0, 62 - offset);
		offset = 62;
	}

	return offset;
}

/**
 * opt_dns_search_dup_ptr() - Look for possible domain name compression pointer
 * @buf:	Current option buffer with existing labels
 * @cmp:	Portion of domain name being added
 * @len:	Length of current option buffer
 *
 * Return: offset to corresponding compression pointer if any, -1 if not found
 */
static int opt_dns_search_dup_ptr(unsigned char *buf, char *cmp, size_t len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		if (buf[i] == 0 &&
		    len - i - 1 >= strlen(cmp) &&
		    !memcmp(buf + i + 1, cmp, strlen(cmp)))
			return i;

		if ((buf[i] & 0xc0) == 0xc0 &&
		    len - i - 2 >= strlen(cmp) &&
		    !memcmp(buf + i + 2, cmp, strlen(cmp)))
			return i + 1;
	}

	return -1;
}

/**
 * opt_set_dns_search() - Fill data and set length for Domain Search option
 * @c:		Execution context
 * @max_len:	Maximum total length of option buffer
 */
static void opt_set_dns_search(struct ctx *c, size_t max_len)
{
	char buf[NS_MAXDNAME];
	int i;

	opts[119].slen = 0;

	for (i = 0; i < 255; i++)
		max_len -= opts[i].slen;

	for (i = 0; *c->dns_search[i].n; i++) {
		unsigned int n;
		int dup = -1;
		char *p;

		buf[0] = 0;
		for (p = c->dns_search[i].n, n = 1; *p; p++) {
			if (*p == '.') {
				/* RFC 1035 4.1.4 Message compression */
				dup = opt_dns_search_dup_ptr(opts[119].s, p + 1,
							     opts[119].slen);

				if (dup >= 0) {
					buf[n++] = '\xc0';
					buf[n++] = dup;
					break;
				}
				buf[n++] = '.';
			} else {
				buf[n++] = *p;
			}
		}

		/* The compression pointer is also an end of label */
		if (dup < 0)
			buf[n++] = 0;

		if (n >= max_len)
			break;

		memcpy(opts[119].s + opts[119].slen, buf, n);
		opts[119].slen += n;
		max_len -= n;
	}

	for (i = 0; i < opts[119].slen; i++) {
		if (!opts[119].s[i] || opts[119].s[i] == '.') {
			opts[119].s[i] = strcspn((char *)opts[119].s + i + 1,
						 ".\xc0");
		}
	}
}

/**
 * dhcp() - Check if this is a DHCP message, reply as needed
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @eh:		Packet buffer, Ethernet header
 *
 * Return: 0 if it's not a DHCP message, 1 if handled, -1 on failure
 */
int dhcp(struct ctx *c, struct ethhdr *eh, size_t len)
{
	struct iphdr *iph = (struct iphdr *)(eh + 1);
	size_t mlen, olen;
	struct udphdr *uh;
	unsigned int i;
	struct msg *m;

	if (len < sizeof(*eh) + sizeof(*iph))
		return 0;

	if (len < sizeof(*eh) + iph->ihl * 4 + sizeof(*uh))
		return 0;

	uh = (struct udphdr *)((char *)iph + iph->ihl * 4);
	m = (struct msg *)(uh + 1);

	if (uh->dest != htons(67))
		return 0;

	if (c->no_dhcp)
		return 1;

	mlen = len - sizeof(*eh) - iph->ihl * 4 - sizeof(*uh);
	if (mlen != ntohs(uh->len) - sizeof(*uh) ||
	    mlen < offsetof(struct msg, o) ||
	    m->op != BOOTREQUEST)
		return -1;

	olen = mlen - offsetof(struct msg, o);
	for (i = 0; i + 2 < olen; i += m->o[i + 1] + 2) {
		if (m->o[i + 1] + i + 2 >= olen)
			return -1;

		memcpy(&opts[m->o[i]].c, &m->o[i + 2], m->o[i + 1]);
	}

	if (opts[53].c[0] == DHCPDISCOVER) {
		info("DHCP: offer to discover");
		opts[53].s[0] = DHCPOFFER;
	} else if (opts[53].c[0] == DHCPREQUEST) {
		info("DHCP: ack to request");
		opts[53].s[0] = DHCPACK;
	} else {
		return -1;
	}

	info("    from %02x:%02x:%02x:%02x:%02x:%02x",
	     m->chaddr[0], m->chaddr[1], m->chaddr[2],
	     m->chaddr[3], m->chaddr[4], m->chaddr[5]);

	m->yiaddr = c->addr4;
	*(unsigned long *)opts[1].s =  c->mask4;
	*(unsigned long *)opts[3].s =  c->gw4;
	*(unsigned long *)opts[54].s = c->gw4;

	/* If the gateway is not on the assigned subnet, send an option 121
	 * (Classless Static Routing) adding a dummy route to it.
	 */
	if ((c->addr4 & c->mask4) != (c->gw4 & c->mask4)) {
		/* a.b.c.d/32:0.0.0.0, 0:a.b.c.d */
		opts[121].slen = 14;
		opts[121].s[0] = 32;
		*(unsigned long *)&opts[121].s[1] = c->gw4;
		*(unsigned long *)&opts[121].s[10] = c->gw4;
	}

	if (c->mtu != -1) {
		opts[26].slen = 2;
		opts[26].s[0] = c->mtu / 256;
		opts[26].s[1] = c->mtu % 256;
	}

	for (i = 0, opts[6].slen = 0; c->dns4[i]; i++) {
		((uint32_t *)opts[6].s)[i] = c->dns4[i];
		opts[6].slen += sizeof(uint32_t);
	}

	opt_set_dns_search(c, sizeof(m->o));

	uh->len = htons(len = offsetof(struct msg, o) + fill(m) + sizeof(*uh));
	uh->check = 0;
	uh->source = htons(67);
	uh->dest = htons(68);

	iph->tot_len = htons(len += sizeof(*iph));
	iph->daddr = c->addr4;
	iph->saddr = c->gw4;
	iph->check = 0;
	iph->check = csum_unaligned(iph, iph->ihl * 4, 0);

	len += sizeof(*eh);
	memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
	memcpy(eh->h_source, c->mac, ETH_ALEN);

	if (tap_send(c, eh, len, 0) < 0)
		perror("DHCP: send");

	return 1;
}

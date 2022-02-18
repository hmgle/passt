// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * dhcpv6.c - Minimalistic DHCPv6 server for PASST
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "util.h"
#include "passt.h"
#include "tap.h"

/**
 * struct opt_hdr - DHCPv6 option header
 * @t:		Option type
 * @l:		Option length, network order
 */
struct opt_hdr {
	uint16_t t;
#if __BYTE_ORDER == __BIG_ENDIAN
# define OPT_CLIENTID		1
# define OPT_SERVERID		2
# define OPT_IA_NA		3
# define OPT_IA_TA		4
# define OPT_IAAADR		5
# define OPT_STATUS_CODE	13
# define  STATUS_NOTONLINK	4
# define OPT_DNS_SERVERS	23
# define OPT_DNS_SEARCH		24
#else
# define OPT_CLIENTID		__bswap_constant_16(1)
# define OPT_SERVERID		__bswap_constant_16(2)
# define OPT_IA_NA		__bswap_constant_16(3)
# define OPT_IA_TA		__bswap_constant_16(4)
# define OPT_IAAADR		__bswap_constant_16(5)
# define OPT_STATUS_CODE	__bswap_constant_16(13)
# define  STATUS_NOTONLINK	__bswap_constant_16(4)
# define OPT_DNS_SERVERS	__bswap_constant_16(23)
# define OPT_DNS_SEARCH		__bswap_constant_16(24)
#endif
#define   STR_NOTONLINK		"Prefix not appropriate for link."

	uint16_t l;
};

#if __BYTE_ORDER == __BIG_ENDIAN
# define OPT_SIZE_CONV(x)	(x)
#else
# define OPT_SIZE_CONV(x)	(__bswap_constant_16(x))
#endif
#define OPT_SIZE(x)		OPT_SIZE_CONV(sizeof(struct opt_##x) -	\
					      sizeof(struct opt_hdr))

/**
 * struct opt_client_id - DHCPv6 Client Identifier option
 * @hdr:		Option header
 * @duid:		Client DUID, up to 128 bytes (cf. RFC 8415, 11.1.)
 */
struct opt_client_id {
	struct opt_hdr hdr;
	uint8_t duid[128];
};

/**
 * struct opt_server_id - DHCPv6 Server Identifier option
 * @hdr:		Option header
 * @duid_type:		Type of server DUID, network order
 * @duid_hw:		IANA hardware type, network order
 * @duid_time:		Time reference, network order
 * @duid_lladdr:	Link-layer address (MAC address)
 */
struct opt_server_id {
	struct opt_hdr hdr;
	uint16_t duid_type;
#define DUID_TYPE_LLT		1

	uint16_t duid_hw;
	uint32_t duid_time;
	uint8_t duid_lladdr[ETH_ALEN];
};

#if __BYTE_ORDER == __BIG_ENDIAN
#define SERVER_ID {						\
	{ OPT_SERVERID,	OPT_SIZE(server_id) },				\
	  DUID_TYPE_LLT, ARPHRD_ETHER, 0, { 0 }				\
}
#else
#define SERVER_ID {						\
	{ OPT_SERVERID,	OPT_SIZE(server_id) },				\
	__bswap_constant_16(DUID_TYPE_LLT),				\
	__bswap_constant_16(ARPHRD_ETHER),				\
	0, { 0 }							\
}
#endif

/**
 * struct opt_ia_na - Identity Association for Non-temporary Addresses Option
 * @hdr:		Option header
 * @iaid:		Unique identifier for IA_NA, network order
 * @t1:			Rebind interval for this server (always infinity)
 * @t2:			Rebind interval for any server (always infinity)
 */
struct opt_ia_na {
	struct opt_hdr hdr;
	uint32_t iaid;
	uint32_t t1;
	uint32_t t2;
};

/**
 * struct opt_ia_ta - Identity Association for Temporary Addresses Option
 * @hdr:		Option header
 * @iaid:		Unique identifier for IA_TA, network order
 */
struct opt_ia_ta {
	struct opt_hdr hdr;
	uint32_t iaid;
};

/**
 * struct opt_ia_addr - IA Address Option
 * @hdr:		Option header
 * @addr:		Leased IPv6 address
 * @pref_lifetime:	Preferred lifetime, network order (always infinity)
 * @valid_lifetime:	Valid lifetime, network order (always infinity)
 */
struct opt_ia_addr {
	struct opt_hdr hdr;
	struct in6_addr addr;
	uint32_t pref_lifetime;
	uint32_t valid_lifetime;
};

/**
 * struct opt_status_code - Status Code Option (used for NotOnLink error only)
 * @hdr:		Option header
 * @code:		Numeric code for status, network order
 * @status_msg:		Text string suitable for display, not NULL-terminated
 */
struct opt_status_code {
	struct opt_hdr hdr;
	uint16_t code;
	char status_msg[sizeof(STR_NOTONLINK) - 1];
};

/**
 * struct opt_dns_servers - DNS Recursive Name Server option (RFC 3646)
 * @hdr:		Option header
 * @addr:		IPv6 DNS addresses
 */
struct opt_dns_servers {
	struct opt_hdr hdr;
	struct in6_addr addr[MAXNS];
};

/**
 * struct opt_dns_servers - Domain Search List option (RFC 3646)
 * @hdr:		Option header
 * @list:		NULL-separated list of domain names
 */
struct opt_dns_search {
	struct opt_hdr hdr;
	char list[MAXDNSRCH * NS_MAXDNAME];
};

/**
 * struct msg_hdr - DHCPv6 client/server message header
 * @type:		DHCP message type
 * @xid:		Transaction ID for message exchange
 */
struct msg_hdr {
	uint32_t type:8;
#define TYPE_SOLICIT			1
#define TYPE_ADVERTISE			2
#define TYPE_REQUEST			3
#define TYPE_CONFIRM			4
#define TYPE_RENEW			5
#define TYPE_REBIND			6
#define TYPE_REPLY			7
#define TYPE_RELEASE			8
#define TYPE_DECLINE			9
#define TYPE_INFORMATION_REQUEST	11

	uint32_t xid:24;
} __attribute__((__packed__));

#if __BYTE_ORDER == __BIG_ENDIAN
#define UH_RESP {{{ 547, 546, 0, 0, }}}
#else
#define UH_RESP {{{ __bswap_constant_16(547), __bswap_constant_16(546), 0, 0 }}}
#endif

/**
 * struct resp_t - Normal advertise and reply message
 * @uh:			UDP header
 * @hdr:		DHCP message header
 * @server_id:		Server Identifier option
 * @ia_na:		Non-temporary Address option
 * @ia_addr:		Address for IA_NA
 * @client_id:		Client Identifier, variable length
 * @dns_servers:	DNS Recursive Name Server, here just for storage size
 * @dns_search:		Domain Search List, here just for storage size
 */
static struct resp_t {
	struct udphdr  uh;
	struct msg_hdr hdr;

	struct opt_server_id server_id;
	struct opt_ia_na ia_na;
	struct opt_ia_addr ia_addr;
	struct opt_client_id client_id;
	struct opt_dns_servers dns_servers;
	struct opt_dns_search dns_search;
} __attribute__((__packed__)) resp = {
	UH_RESP,
	{ 0 },
	SERVER_ID,

	{ { OPT_IA_NA,		OPT_SIZE_CONV(sizeof(struct opt_ia_na) +
					      sizeof(struct opt_ia_addr) -
					      sizeof(struct opt_hdr)) },
	  1, (uint32_t)~0U, (uint32_t)~0U
	},

	{ { OPT_IAAADR,		OPT_SIZE(ia_addr) },
	  IN6ADDR_ANY_INIT, (uint32_t)~0U, (uint32_t)~0U
	},

	{ { OPT_CLIENTID,	0, },
	  { 0 }
	},

	{ { OPT_DNS_SERVERS,	0, },
	  { IN6ADDR_ANY_INIT }
	},

	{ { OPT_DNS_SEARCH,	0, },
	  { 0 },
	},
};

static const struct opt_status_code sc_not_on_link = {
	{ OPT_STATUS_CODE,	OPT_SIZE(status_code), },
	STATUS_NOTONLINK, STR_NOTONLINK
};

/**
 * struct resp_not_on_link_t - NotOnLink error (mandated by RFC 8415, 18.3.2.)
 * @uh:			UDP header
 * @hdr:		DHCP message header
 * @server_id:		Server Identifier option
 * @var:		Payload: IA_NA from client, status code, client ID
 */
static struct resp_not_on_link_t {
	struct udphdr  uh;
	struct msg_hdr hdr;

	struct opt_server_id server_id;

	uint8_t var[sizeof(struct opt_ia_na) + sizeof(struct opt_status_code) +
		    sizeof(struct opt_client_id)];
} __attribute__((__packed__)) resp_not_on_link = {
	UH_RESP,
	{ TYPE_REPLY, 0 },
	SERVER_ID,
	{ 0, },
};

/**
 * dhcpv6_opt() - Get option from DHCPv6 message
 * @o:			First option header to check
 * @type:		Option type to look up, network order
 * @len:		Remaining length, host order, modified on return
 *
 * Return: pointer to option header, or NULL on malformed or missing option
 */
static struct opt_hdr *dhcpv6_opt(struct opt_hdr *o, uint16_t type, size_t *len)
{
	while (*len >= sizeof(struct opt_hdr)) {
		unsigned int opt_len = ntohs(o->l) + sizeof(struct opt_hdr);

		if (opt_len > *len)
			return NULL;

		*len -= opt_len;

		if (o->t == type)
			return o;

		o = (struct opt_hdr *)((uint8_t *)o + opt_len);
	}

	return NULL;
}

/**
 * dhcpv6_ia_notonlink() - Check if any IA contains non-appropriate addresses
 * @o:			First option header to check for IAs
 * @rem_len:		Remaining message length, host order
 * @addr:		Address we want to lease to the client
 *
 * Return: pointer to non-appropriate IA_NA or IA_TA, if any, NULL otherwise
 */
static struct opt_hdr *dhcpv6_ia_notonlink(struct opt_hdr *o, size_t rem_len,
					   struct in6_addr *addr)
{
	struct opt_hdr *ia, *ia_addr;
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr *req_addr;
	size_t len;
	int ia_type;

	ia_type = OPT_IA_NA;
ia_ta:
	len = rem_len;
	ia = o;

	while ((ia = dhcpv6_opt(ia, ia_type, &len))) {
		size_t ia_len = ntohs(ia->l);

		if (ia_type == OPT_IA_NA) {
			struct opt_ia_na *subopt = (struct opt_ia_na *)ia + 1;

			ia_addr = (struct opt_hdr *)subopt;
		} else if (ia_type == OPT_IA_TA) {
			struct opt_ia_ta *subopt = (struct opt_ia_ta *)ia + 1;

			ia_addr = (struct opt_hdr *)subopt;
		}

		ia_len -= sizeof(struct opt_ia_na) - sizeof(struct opt_hdr);

		while ((ia_addr = dhcpv6_opt(ia_addr, OPT_IAAADR, &ia_len))) {
			struct opt_ia_addr *next;

			req_addr = (struct in6_addr *)(ia_addr + 1);

			if (memcmp(addr, req_addr, sizeof(*addr))) {
				info("DHCPv6: requested address %s not on link",
				     inet_ntop(AF_INET6, req_addr,
					       buf, sizeof(buf)));
				return ia;
			}

			next = (struct opt_ia_addr *)ia_addr + 1;
			ia_addr = (struct opt_hdr *)next;
		}

		if (!ia_addr)
			break;

		ia = ia_addr;
	}

	if (ia_type == OPT_IA_NA) {
		ia_type = OPT_IA_TA;
		goto ia_ta;
	}

	return NULL;
}

/**
 * dhcpv6_dns_fill() - Fill in DNS Servers and Domain Search list options
 * @c:		Execution context
 * @buf:	Response message buffer where options will be appended
 * @offset:	Offset in message buffer for new options
 *
 * Return: updated length of response message buffer.
 */
static size_t dhcpv6_dns_fill(struct ctx *c, char *buf, int offset)
{
	struct opt_dns_servers *srv = NULL;
	struct opt_dns_search *srch = NULL;
	char *p = NULL;
	int i;

	if (c->no_dhcp_dns)
		goto search;

	for (i = 0; !IN6_IS_ADDR_UNSPECIFIED(&c->dns6[i]); i++) {
		if (!i) {
			srv = (struct opt_dns_servers *)(buf + offset);
			offset += sizeof(struct opt_hdr);
			srv->hdr.t = OPT_DNS_SERVERS;
			srv->hdr.l = 0;
		}

		memcpy(&srv->addr[i], &c->dns6[i], sizeof(srv->addr[i]));
		srv->hdr.l += sizeof(srv->addr[i]);
		offset += sizeof(srv->addr[i]);
	}

	if (srv)
		srv->hdr.l = htons(srv->hdr.l);

search:
	if (c->no_dhcp_dns_search)
		return offset;

	for (i = 0; *c->dns_search[i].n; i++) {
		if (!i) {
			srch = (struct opt_dns_search *)(buf + offset);
			offset += sizeof(struct opt_hdr);
			srch->hdr.t = OPT_DNS_SEARCH;
			srch->hdr.l = 0;
			p = srch->list;
			*p = 0;
		}

		p = stpcpy(p + 1, c->dns_search[i].n);
		*(p++) = 0;
		srch->hdr.l += strlen(c->dns_search[i].n) + 2;
		offset += strlen(c->dns_search[i].n) + 2;
	}

	if (srch) {
		for (i = 0; i < srch->hdr.l; i++) {
			if (srch->list[i] == '.' || !srch->list[i]) {
				srch->list[i] = strcspn(srch->list + i + 1,
							".");
			}
		}
		srch->hdr.l = htons(srch->hdr.l);
	}

	return offset;
}

/**
 * dhcpv6() - Check if this is a DHCPv6 message, reply as needed
 * @c:		Execution context
 * @eh:		Packet buffer, Ethernet header
 * @len:	Total L2 packet length
 *
 * Return: 0 if it's not a DHCPv6 message, 1 if handled, -1 on failure
 */
int dhcpv6(struct ctx *c, struct ethhdr *eh, size_t len)
{
	struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
	struct opt_hdr *ia, *bad_ia, *client_id, *server_id;
	struct in6_addr *src;
	struct msg_hdr *mh;
	struct udphdr *uh;
	uint8_t proto;
	size_t mlen;
	size_t n;

	uh = (struct udphdr *)ipv6_l4hdr(ip6h, &proto);
	if (!uh || proto != IPPROTO_UDP || uh->dest != htons(547))
		return 0;

	if (c->no_dhcpv6)
		return 1;

	if (!IN6_IS_ADDR_MULTICAST(&ip6h->daddr))
		return -1;

	mlen = len - ((intptr_t)uh - (intptr_t)eh) - sizeof(*uh);

	if (mlen != ntohs(uh->len) - sizeof(*uh) ||
	    mlen < sizeof(struct msg_hdr))
		return -1;

	c->addr6_ll_seen = ip6h->saddr;

	if (IN6_IS_ADDR_LINKLOCAL(&c->gw6))
		src = &c->gw6;
	else
		src = &c->addr6_ll;

	mh = (struct msg_hdr *)(uh + 1);
	mlen -= sizeof(struct msg_hdr);

	n = mlen;
	client_id = dhcpv6_opt((struct opt_hdr *)(mh + 1), OPT_CLIENTID, &n);
	if (!client_id || ntohs(client_id->l) > ntohs(OPT_SIZE(client_id)))
		return -1;

	n = mlen;
	server_id = dhcpv6_opt((struct opt_hdr *)(mh + 1), OPT_SERVERID, &n);

	n = mlen;
	ia = dhcpv6_opt((struct opt_hdr *)(mh + 1), OPT_IA_NA, &n);
	if (ia && ntohs(ia->l) < ntohs(OPT_SIZE(ia_na)))
		return -1;

	resp.hdr.type = TYPE_REPLY;
	switch (mh->type) {
	case TYPE_REQUEST:
	case TYPE_RENEW:
		if (!server_id ||
		    memcmp(&resp.server_id, server_id, sizeof(resp.server_id)))
			return -1;
		/* Falls through */
	case TYPE_CONFIRM:
		if (mh->type == TYPE_CONFIRM && server_id)
			return -1;

		if ((bad_ia = dhcpv6_ia_notonlink((struct opt_hdr *)(mh + 1),
						  mlen, &c->addr6))) {
			info("DHCPv6: received CONFIRM with inappropriate IA,"
			     " sending NotOnLink status in REPLY");

			n = ntohs(bad_ia->l) + sizeof(struct opt_hdr);
			bad_ia->l = htons(n - sizeof(struct opt_hdr) +
					  sizeof(sc_not_on_link));
			memcpy(resp_not_on_link.var, bad_ia, n);

			memcpy(resp_not_on_link.var + n, &sc_not_on_link,
			       sizeof(sc_not_on_link));
			n += sizeof(sc_not_on_link);

			memcpy(resp_not_on_link.var + n, client_id,
			       sizeof(struct opt_hdr) + ntohs(client_id->l));
			n += sizeof(struct opt_hdr) + ntohs(client_id->l);

			n = offsetof(struct resp_not_on_link_t, var) + n;
			resp_not_on_link.uh.len = htons(n);

			resp_not_on_link.hdr.xid = mh->xid;

			tap_ip_send(c, src, IPPROTO_UDP,
				    (char *)&resp_not_on_link, n, mh->xid);

			return 1;
		}

		info("DHCPv6: received REQUEST/RENEW/CONFIRM, sending REPLY");
		break;
	case TYPE_INFORMATION_REQUEST:
		if (server_id &&
		    memcmp(&resp.server_id, server_id, sizeof(resp.server_id)))
			return -1;

		n = mlen;
		if (ia || dhcpv6_opt((struct opt_hdr *)(mh + 1), OPT_IA_TA, &n))
			return -1;

		info("DHCPv6: received INFORMATION_REQUEST, sending REPLY");
		break;
	case TYPE_REBIND:
		if (!server_id ||
		    memcmp(&resp.server_id, server_id, sizeof(resp.server_id)))
			return -1;

		info("DHCPv6: received REBIND, sending REPLY");
		break;
	case TYPE_SOLICIT:
		if (server_id)
			return -1;

		resp.hdr.type = TYPE_ADVERTISE;

		info("DHCPv6: received SOLICIT, sending ADVERTISE");
		break;
	default:
		return -1;
	}
	if (ia)
		resp.ia_na.iaid = ((struct opt_ia_na *)ia)->iaid;

	memcpy(&resp.client_id, client_id,
	       ntohs(client_id->l) + sizeof(struct opt_hdr));

	n = offsetof(struct resp_t, client_id) +
	    sizeof(struct opt_hdr) + ntohs(client_id->l);
	n = dhcpv6_dns_fill(c, (char *)&resp, n);
	resp.uh.len = htons(n);

	resp.hdr.xid = mh->xid;

	tap_ip_send(c, src, IPPROTO_UDP, (char *)&resp, n, mh->xid);
	c->addr6_seen = c->addr6;

	return 1;
}

/**
 * dhcpv6_init() - Initialise DUID and addresses for DHCPv6 server
 * @c:		Execution context
 */
void dhcpv6_init(struct ctx *c)
{
	time_t y2k = 946684800; /* Epoch to 2000-01-01T00:00:00Z, no mktime() */
	uint32_t duid_time;

	duid_time = htonl(difftime(time(NULL), y2k));

	resp.server_id.duid_time		= duid_time;
	resp_not_on_link.server_id.duid_time	= duid_time;

	memcpy(resp.server_id.duid_lladdr,		c->mac, sizeof(c->mac));
	memcpy(resp_not_on_link.server_id.duid_lladdr,	c->mac, sizeof(c->mac));

	resp.ia_addr.addr	= c->addr6;
}

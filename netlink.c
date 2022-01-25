// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * netlink.c - rtnetlink routines: interfaces, addresses, routes
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <sched.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "util.h"
#include "passt.h"
#include "netlink.h"

/* Socket in init, in target namespace, sequence (just needs to be monotonic) */
static int nl_sock	= -1;
static int nl_sock_ns	= -1;
static int nl_seq;

/**
 * nl_sock_init_do() - Set up netlink sockets in init and target namespace
 * @arg:	Execution context
 *
 * Return: 0
 */
static int nl_sock_init_do(void *arg)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK, };
	int *s = &nl_sock;
#ifdef NETLINK_GET_STRICT_CHK
	int y = 1;
#endif

ns:
	if (((*s) = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0 ||
	    bind(*s, (struct sockaddr *)&addr, sizeof(addr)))
		*s = -1;

	if (*s == -1 || !arg || s == &nl_sock_ns)
		return 0;

#ifdef NETLINK_GET_STRICT_CHK
	setsockopt(*s, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &y, sizeof(y));
#endif

	ns_enter((struct ctx *)arg);
	s = &nl_sock_ns;
	goto ns;
}

/**
 * nl_sock_init() - Call nl_sock_init_do() and check for failures
 * @c:		Execution context
 *
 * Return: -EIO if sockets couldn't be set up, 0 otherwise
 */
int nl_sock_init(struct ctx *c)
{
	if (c->mode == MODE_PASTA) {
		NS_CALL(nl_sock_init_do, c);
		if (nl_sock_ns == -1)
			return -EIO;
	} else {
		nl_sock_init_do(NULL);
	}

	if (nl_sock == -1)
		return -EIO;

	return 0;
}

/**
 * nl_req() - Send netlink request and read response
 * @ns:		Use netlink socket in namespace
 * @buf:	Buffer for response (at least BUFSIZ long)
 * @req:	Request with netlink header
 * @len:	Request length
 *
 * Return: received length on success, negative error code on failure
 */
static int nl_req(int ns, char *buf, void *req, ssize_t len)
{
	int s = ns ? nl_sock_ns : nl_sock, done = 0;
	char flush[BUFSIZ];
	ssize_t n;

	while (!done && (n = recv(s, flush, sizeof(flush), MSG_DONTWAIT)) > 0) {
		struct nlmsghdr *nh = (struct nlmsghdr *)flush;
		size_t nm = n;

		for ( ; NLMSG_OK(nh, nm); nh = NLMSG_NEXT(nh, nm)) {
			if (nh->nlmsg_type == NLMSG_DONE ||
			    nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
		}
	}

	if ((send(s, req, len, 0) < len) || (len = recv(s, buf, BUFSIZ, 0)) < 0)
		return -errno;

	return len;
}

/**
 * nl_get_ext_if() - Get interface index supporting IP versions being probed
 * @v4:		Probe IPv4 support, set to ENABLED or DISABLED on return
 * @v6:		Probe IPv4 support, set to ENABLED or DISABLED on return
 *
 * Return: interface index, 0 if not found
 */
unsigned int nl_get_ext_if(int *v4, int *v6)
{
	struct { struct nlmsghdr nlh; struct rtmsg rtm; } req = {
		.nlh.nlmsg_type	 = RTM_GETROUTE,
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.nlh.nlmsg_len	 = NLMSG_LENGTH(sizeof(struct rtmsg)),
		.nlh.nlmsg_seq	 = nl_seq++,

		.rtm.rtm_table	 = RT_TABLE_MAIN,
		.rtm.rtm_scope	 = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	 = RTN_UNICAST,
	};
	unsigned int i, first_v4 = 0, first_v6 = 0;
	uint8_t has_v4[PAGE_SIZE * 8 / 8] = { 0 }; /* See __dev_alloc_name() */
	uint8_t has_v6[PAGE_SIZE * 8 / 8] = { 0 }; /* in kernel */
	struct nlmsghdr *nh;
	struct rtattr *rta;
	struct rtmsg *rtm;
	char buf[BUFSIZ];
	long *word, tmp;
	uint8_t *vmap;
	size_t n, na;
	int *v;

	if (*v4 == IP_VERSION_PROBE) {
		v = v4;
		req.rtm.rtm_family = AF_INET;
		vmap = has_v4;
	} else if (*v6 == IP_VERSION_PROBE) {
v6:
		v = v6;
		req.rtm.rtm_family = AF_INET6;
		vmap = has_v6;
	} else {
		return 0;
	}

	n = nl_req(0, buf, &req, sizeof(req));
	nh = (struct nlmsghdr *)buf;

	for ( ; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n)) {
		rtm = (struct rtmsg *)NLMSG_DATA(nh);

		if (rtm->rtm_dst_len || rtm->rtm_family != req.rtm.rtm_family)
			continue;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			unsigned int ifi;

			if (rta->rta_type != RTA_OIF)
				continue;

			ifi = *(unsigned int *)RTA_DATA(rta);

			if (*v4 == IP_VERSION_DISABLED ||
			    *v6 == IP_VERSION_DISABLED) {
				*v = IP_VERSION_ENABLED;
				return ifi;
			}

			if (v == v4 && !first_v4)
				first_v4 = ifi;

			if (v == v6 && !first_v6)
				first_v6 = ifi;

			bitmap_set(vmap, ifi);
		}
	}

	if (v == v4 && *v6 == IP_VERSION_PROBE) {
		req.nlh.nlmsg_seq = nl_seq++;
		goto v6;
	}

	word = (long *)has_v4;
	for (i = 0; i < ARRAY_SIZE(has_v4) / sizeof(long); i++, word++) {
		tmp = *word;
		while ((n = ffsl(tmp))) {
			int ifi = i * sizeof(long) * 8 + n - 1;

			if (!first_v4)
				first_v4 = ifi;

			tmp &= ~(1UL << (n - 1));
			if (bitmap_isset(has_v6, ifi)) {
				*v4 = *v6 = IP_VERSION_ENABLED;
				return ifi;
			}
		}
	}

	if (first_v4) {
		*v4 = IP_VERSION_ENABLED;
		*v6 = IP_VERSION_DISABLED;
		return first_v4;
	}

	if (first_v6) {
		*v4 = IP_VERSION_DISABLED;
		*v6 = IP_VERSION_ENABLED;
		return first_v6;
	}

	err("No external routable interface for any IP protocol");
	return 0;
}

/**
 * nl_route() - Get/set default gateway for given interface and address family
 * @ns:		Use netlink socket in namespace
 * @ifi:	Interface index
 * @af:		Address family
 * @gw:		Default gateway to fill if zero, to set if not
 */
void nl_route(int ns, unsigned int ifi, sa_family_t af, void *gw)
{
	int set = (af == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(gw)) ||
		  (af == AF_INET && *(uint32_t *)gw);
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
		union {
			struct {
				struct rtattr rta_dst;
				struct in6_addr d;
				struct rtattr rta_gw;
				struct in6_addr a;
			} r6;
			struct {
				struct rtattr rta_dst;
				uint32_t d;
				struct rtattr rta_gw;
				uint32_t a;
				uint8_t end;
			} r4;
		} set;
	} req = {
		.nlh.nlmsg_type	  = set ? RTM_NEWROUTE : RTM_GETROUTE,
		.nlh.nlmsg_flags  = NLM_F_REQUEST,
		.nlh.nlmsg_seq	  = nl_seq++,

		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi,
	};
	struct nlmsghdr *nh;
	struct rtattr *rta;
	struct rtmsg *rtm;
	char buf[BUFSIZ];
	size_t n, na;

	if (set) {
		if (af == AF_INET6) {
			size_t rta_len = RTA_LENGTH(sizeof(req.set.r6.d));

			req.nlh.nlmsg_len = sizeof(req);

			req.set.r6.rta_dst.rta_type = RTA_DST;
			req.set.r6.rta_dst.rta_len = rta_len;

			memcpy(&req.set.r6.a, gw, sizeof(req.set.r6.a));
			req.set.r6.rta_gw.rta_type = RTA_GATEWAY;
			req.set.r6.rta_gw.rta_len = rta_len;
		} else {
			size_t rta_len = RTA_LENGTH(sizeof(req.set.r4.d));

			req.nlh.nlmsg_len = offsetof(struct req_t, set.r4.end);

			req.set.r4.rta_dst.rta_type = RTA_DST;
			req.set.r4.rta_dst.rta_len = rta_len;

			req.set.r4.a = *(uint32_t *)gw;
			req.set.r4.rta_gw.rta_type = RTA_GATEWAY;
			req.set.r4.rta_gw.rta_len = rta_len;
		}

		req.rtm.rtm_protocol = RTPROT_BOOT;
		req.nlh.nlmsg_flags |= NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
	} else {
		req.nlh.nlmsg_len = offsetof(struct req_t, set.r6);
		req.nlh.nlmsg_flags |= NLM_F_DUMP;
	}

	n = nl_req(ns, buf, &req, req.nlh.nlmsg_len);
	if (set)
		return;

	nh = (struct nlmsghdr *)buf;
	for ( ; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n)) {
		if (nh->nlmsg_type != RTM_NEWROUTE)
			goto next;

		rtm = (struct rtmsg *)NLMSG_DATA(nh);
		if (rtm->rtm_dst_len)
			continue;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != RTA_GATEWAY)
				continue;

			memcpy(gw, RTA_DATA(rta), RTA_PAYLOAD(rta));
			return;
		}

next:
		if (nh->nlmsg_type == NLMSG_DONE)
			break;
	}
}

/**
 * nl_addr() - Get/set IP addresses
 * @ns:		Use netlink socket in namespace
 * @ifi:	Interface index
 * @af:		Address family
 * @addr:	Global address to fill if zero, to set if not, ignored if NULL
 * @prefix_len:	Mask or prefix length, set or fetched (for IPv4)
 * @addr_l:	Link-scoped address to fill, NULL if not requested
 */
void nl_addr(int ns, unsigned int ifi, sa_family_t af,
	     void *addr, int *prefix_len, void *addr_l)
{
	int set = addr && ((af == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(addr)) ||
			   (af == AF_INET && *(uint32_t *)addr));
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		union {
			struct {
				struct rtattr rta_l;
				uint32_t l;
				struct rtattr rta_a;
				uint32_t a;

				uint8_t end;
			} a4;
			struct {
				struct rtattr rta_l;
				struct in6_addr l;
				struct rtattr rta_a;
				struct in6_addr a;
			} a6;
		} set;
	} req = {
		.nlh.nlmsg_type    = set ? RTM_NEWADDR : RTM_GETADDR,
		.nlh.nlmsg_flags   = NLM_F_REQUEST,
		.nlh.nlmsg_len     = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
		.nlh.nlmsg_seq     = nl_seq++,

		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi,
		.ifa.ifa_prefixlen = *prefix_len,
	};
	struct ifaddrmsg *ifa;
	struct nlmsghdr *nh;
	struct rtattr *rta;
	char buf[BUFSIZ];
	size_t n, na;

	if (set) {
		if (af == AF_INET6) {
			size_t rta_len = RTA_LENGTH(sizeof(req.set.a6.l));

			req.nlh.nlmsg_len = sizeof(req);

			memcpy(&req.set.a6.l, addr, sizeof(req.set.a6.l));
			req.set.a6.rta_l.rta_len = rta_len;
			req.set.a4.rta_l.rta_type = IFA_LOCAL;
			memcpy(&req.set.a6.a, addr, sizeof(req.set.a6.a));
			req.set.a6.rta_a.rta_len = rta_len;
			req.set.a6.rta_a.rta_type = IFA_ADDRESS;
		} else {
			size_t rta_len = RTA_LENGTH(sizeof(req.set.a4.l));

			req.nlh.nlmsg_len = offsetof(struct req_t, set.a4.end);

			req.set.a4.l = req.set.a4.a = *(uint32_t *)addr;
			req.set.a4.rta_l.rta_len = rta_len;
			req.set.a4.rta_l.rta_type = IFA_LOCAL;
			req.set.a4.rta_a.rta_len = rta_len;
			req.set.a4.rta_a.rta_type = IFA_ADDRESS;
		}

		req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_ACK | NLM_F_EXCL;
	} else {
		req.nlh.nlmsg_flags |= NLM_F_DUMP;
	}

	n = nl_req(ns, buf, &req, req.nlh.nlmsg_len);
	if (set)
		return;

	nh = (struct nlmsghdr *)buf;
	for ( ; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n)) {
		if (nh->nlmsg_type != RTM_NEWADDR)
			goto next;

		ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
		if (ifa->ifa_index != ifi)
			goto next;

		for (rta = IFA_RTA(ifa), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != IFA_ADDRESS)
				continue;

			if (af == AF_INET && addr && !*(uint32_t *)addr) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
				*prefix_len = ifa->ifa_prefixlen;
			} else if (af == AF_INET6 && addr &&
				 ifa->ifa_scope == RT_SCOPE_UNIVERSE &&
				 IN6_IS_ADDR_UNSPECIFIED(addr)) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
			}

			if (addr_l &&
			    af == AF_INET6 && ifa->ifa_scope == RT_SCOPE_LINK &&
			    IN6_IS_ADDR_UNSPECIFIED(addr_l))
				memcpy(addr_l, RTA_DATA(rta), RTA_PAYLOAD(rta));
		}
next:
		if (nh->nlmsg_type == NLMSG_DONE)
			break;
	}
}

/**
 * nl_link() - Get/set link attributes
 * @ns:		Use netlink socket in namespace
 * @ifi:	Interface index
 * @mac:	MAC address to fill, if passed as zero, to set otherwise
 * @up:		If set, bring up the link
 * @mtu:	If non-zero, set interface MTU
 */
void nl_link(int ns, unsigned int ifi, void *mac, int up, int mtu)
{
	int change = !MAC_IS_ZERO(mac) || up || mtu;
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		struct rtattr rta;
		union {
			unsigned char mac[ETH_ALEN];
			unsigned int mtu;
		} set;
	} req = {
		.nlh.nlmsg_type   = change ? RTM_NEWLINK : RTM_GETLINK,
		.nlh.nlmsg_len    = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nlh.nlmsg_flags  = NLM_F_REQUEST | (change ? NLM_F_ACK : 0),
		.nlh.nlmsg_seq	  = nl_seq++,
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
		.ifm.ifi_flags	  = up ? IFF_UP : 0,
		.ifm.ifi_change	  = up ? IFF_UP : 0,
	};
	struct ifinfomsg *ifm;
	struct nlmsghdr *nh;
	struct rtattr *rta;
	char buf[BUFSIZ];
	size_t n, na;

	if (!MAC_IS_ZERO(mac)) {
		req.nlh.nlmsg_len = sizeof(req);
		memcpy(req.set.mac, mac, ETH_ALEN);
		req.rta.rta_type = IFLA_ADDRESS;
		req.rta.rta_len = RTA_LENGTH(ETH_ALEN);
		nl_req(ns, buf, &req, req.nlh.nlmsg_len);
		up = 0;
	}

	if (mtu) {
		req.nlh.nlmsg_len = sizeof(req);
		req.set.mtu = mtu;
		req.rta.rta_type = IFLA_MTU;
		req.rta.rta_len = RTA_LENGTH(sizeof(unsigned int));
		nl_req(ns, buf, &req, req.nlh.nlmsg_len);
		up = 0;
	}

	if (up)
		nl_req(ns, buf, &req, req.nlh.nlmsg_len);

	if (change)
		return;

	n = nl_req(ns, buf, &req, req.nlh.nlmsg_len);

	nh = (struct nlmsghdr *)buf;
	for ( ; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n)) {
		if (nh->nlmsg_type != RTM_NEWLINK)
			goto next;

		ifm = (struct ifinfomsg *)NLMSG_DATA(nh);

		for (rta = IFLA_RTA(ifm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != IFLA_ADDRESS)
				continue;

			memcpy(mac, RTA_DATA(rta), ETH_ALEN);
			break;
		}
next:
		if (nh->nlmsg_type == NLMSG_DONE)
			break;
	}
}

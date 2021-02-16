// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *
 * passt.c - Daemon implementation
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * Grab Ethernet frames via AF_UNIX socket, build SOCK_DGRAM/SOCK_STREAM sockets
 * for each 5-tuple from TCP, UDP packets, perform connection tracking and
 * forward them. Forward packets received on sockets back to the UNIX domain
 * socket (typically, a socket virtio_net file descriptor from qemu).
 */

#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/if_link.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <time.h>

#include "passt.h"
#include "arp.h"
#include "dhcp.h"
#include "ndp.h"
#include "util.h"
#include "tcp.h"
#include "udp.h"

#define EPOLL_EVENTS		10

#define EPOLL_TIMEOUT		100 /* ms, for protocol periodic handlers */
#define PERIODIC_HANDLER_FAST	100
#define PERIODIC_HANDLER_SLOW	1000

/**
 * sock_unix() - Create and bind AF_UNIX socket, add to epoll list
 *
 * Return: newly created socket, doesn't return on error
 */
static int sock_unix(void)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = UNIX_SOCK_PATH,
	};

	if (fd < 0) {
		perror("UNIX socket");
		exit(EXIT_FAILURE);
	}

	unlink(UNIX_SOCK_PATH);
	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("UNIX socket bind");
		exit(EXIT_FAILURE);
	}
	return fd;
}

/**
 * struct nl_request - Netlink request filled and sent by get_routes()
 * @nlh:	Netlink message header
 * @rtm:	Routing Netlink message
 */
struct nl_request {
	struct nlmsghdr nlh;
	struct rtmsg rtm;
};

/**
 * get_routes() - Get default route and fill in routable interface name
 * @c:		Execution context
 */
static void get_routes(struct ctx *c)
{
	struct nl_request req = {
		.nlh.nlmsg_type = RTM_GETROUTE,
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_EXCL,
		.nlh.nlmsg_len = sizeof(struct nl_request),
		.nlh.nlmsg_seq = 1,
		.rtm.rtm_family = AF_INET,
		.rtm.rtm_table = RT_TABLE_MAIN,
		.rtm.rtm_scope = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type = RTN_UNICAST,
	};
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
	};
	struct nlmsghdr *nlh;
	struct rtattr *rta;
	struct rtmsg *rtm;
	char buf[BUFSIZ];
	int s, n, na;

	c->v6 = -1;

	s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("netlink socket");
		goto out;
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("netlink bind");
		goto out;
	}

v6:
	if (send(s, &req, sizeof(req), 0) < 0) {
		perror("netlink send");
		goto out;
	}

	n = recv(s, &buf, sizeof(buf), 0);
	if (n < 0) {
		perror("netlink recv");
		goto out;
	}

	nlh = (struct nlmsghdr *)buf;
	for ( ; NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n)) {
		rtm = (struct rtmsg *)NLMSG_DATA(nlh);

		if (rtm->rtm_dst_len ||
		    (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6))
			continue;

		rta = (struct rtattr *)RTM_RTA(rtm);
		na = RTM_PAYLOAD(nlh);
		for ( ; RTA_OK(rta, na); rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type == RTA_GATEWAY &&
			    rtm->rtm_family == AF_INET && !c->v4) {
				memcpy(&c->gw4, RTA_DATA(rta), sizeof(c->gw4));
				c->v4 = 1;
			}

			if (rta->rta_type == RTA_GATEWAY &&
			    rtm->rtm_family == AF_INET6 && !c->v6) {
				memcpy(&c->gw6, RTA_DATA(rta), sizeof(c->gw6));
				c->v6 = 1;
			}

			if (rta->rta_type == RTA_OIF && !*c->ifn) {
				if_indextoname(*(unsigned *)RTA_DATA(rta),
					       c->ifn);
			}
		}

		if (nlh->nlmsg_type == NLMSG_DONE)
			break;
	}

	if (c->v6 == -1) {
		c->v6 = 0;
		req.rtm.rtm_family = AF_INET6;
		req.nlh.nlmsg_seq++;
		recv(s, &buf, sizeof(buf), 0);
		goto v6;
	}

out:
	close(s);

	if (!(c->v4 || c->v6) || !*c->ifn) {
		fprintf(stderr, "No routing information\n");
		exit(EXIT_FAILURE);
	}
}

/**
 * get_addrs() - Fetch MAC, IP addresses, masks of external routable interface
 * @c:		Execution context
 */
static void get_addrs(struct ctx *c)
{
	struct ifreq ifr = {
		.ifr_addr.sa_family = AF_INET,
	};
	struct ifaddrs *ifaddr, *ifa;
	int s, v4 = 0, v6 = 0;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		goto out;
	}

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_in *in_addr;
		struct sockaddr_in6 *in6_addr;

		if (strcmp(ifa->ifa_name, c->ifn))
			continue;

		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET && !v4) {
			in_addr = (struct sockaddr_in *)ifa->ifa_addr;
			c->addr4 = in_addr->sin_addr.s_addr;
			in_addr = (struct sockaddr_in *)ifa->ifa_netmask;
			c->mask4 = in_addr->sin_addr.s_addr;
			v4 = 1;
		} else if (ifa->ifa_addr->sa_family == AF_INET6 && !v6) {
			in6_addr = (struct sockaddr_in6 *)ifa->ifa_addr;
			memcpy(&c->addr6, &in6_addr->sin6_addr,
			       sizeof(c->addr6));
			v6 = 1;
		}

		if (v4 == c->v4 && v6 == c->v6)
			break;
	}

	freeifaddrs(ifaddr);

	if (v4 != c->v4 || v6 != c->v6)
		goto out;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket SIOCGIFHWADDR");
		goto out;
	}

	strncpy(ifr.ifr_name, c->ifn, IF_NAMESIZE);
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
		perror("SIOCGIFHWADDR");
		goto out;
	}

	close(s);
	memcpy(c->mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return;
out:
	fprintf(stderr, "Couldn't get addresses for routable interface\n");
	exit(EXIT_FAILURE);
}

/**
 * get_dns() - Get nameserver addresses from local /etc/resolv.conf
 * @c:		Execution context
 */
static void get_dns(struct ctx *c)
{
	char buf[BUFSIZ], *p, *end;
	int dns4 = 0, dns6 = 0;
	FILE *r;

	r = fopen("/etc/resolv.conf", "r");
	while (fgets(buf, BUFSIZ, r) && !(dns4 && dns6)) {
		if (!strstr(buf, "nameserver "))
			continue;
		p = strrchr(buf, ' ');
		end = strpbrk(buf, "%\n");
		if (end)
			*end = 0;
		if (p && inet_pton(AF_INET, p + 1, &c->dns4))
			dns4 = 1;
		if (p && inet_pton(AF_INET6, p + 1, &c->dns6))
			dns6 = 1;
	}

	fclose(r);
	if (dns4 || dns6)
		return;

	fprintf(stderr, "Couldn't get any nameserver address\n");
	exit(EXIT_FAILURE);
}

/**
 * tap4_handler() - IPv4 packet handler for tap file descriptor
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @in:		Packet buffer, L2 headers
 */
static void tap4_handler(struct ctx *c, char *in, size_t len)
{
	struct ethhdr *eh = (struct ethhdr *)in;
	struct iphdr *iph = (struct iphdr *)(eh + 1);
	char *l4h = (char *)iph + iph->ihl * 4;
	char buf_s[BUFSIZ], buf_d[BUFSIZ];

	if (arp(c, len, eh) || dhcp(c, len, eh))
		return;

	if (iph->protocol == IPPROTO_ICMP) {
		fprintf(stderr, "icmp from tap: %s -> %s\n",
			inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
			inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)));
	} else {
		struct tcphdr *th = (struct tcphdr *)l4h;

		fprintf(stderr, "%s from tap: %s:%i -> %s:%i\n",
			getprotobynumber(iph->protocol)->p_name,
			inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
			ntohs(th->source),
			inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)),
			ntohs(th->dest));
	}

	len -= (intptr_t)l4h - (intptr_t)eh;

	if (iph->protocol == IPPROTO_TCP)
		tcp_tap_handler(c, AF_INET, &iph->daddr, l4h, len);
	else if (iph->protocol == IPPROTO_UDP)
		udp_tap_handler(c, AF_INET, &iph->daddr, l4h, len);
}

/**
 * tap6_handler() - IPv6 packet handler for tap file descriptor
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @in:		Packet buffer, L2 headers
 */
static void tap6_handler(struct ctx *c, char *in, size_t len)
{
	struct ethhdr *eh = (struct ethhdr *)in;
	struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
	char buf_s[BUFSIZ], buf_d[BUFSIZ];
	uint8_t proto;
	char *l4h;

	if (ndp(c, len, eh))
		return;

	l4h = ipv6_l4hdr(ip6h, &proto);

	/* TODO: Assign MAC address to guest so that, together with prefix
	 * assigned via NDP, address matches the one on the host. Then drop
	 * address change and checksum recomputation.
	 */
	c->addr6_guest = ip6h->saddr;
	ip6h->saddr = c->addr6;
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

	if (proto == IPPROTO_ICMPV6) {
		fprintf(stderr, "icmpv6 from tap: %s ->\n\t%s\n",
			inet_ntop(AF_INET6, &ip6h->saddr, buf_s, sizeof(buf_s)),
			inet_ntop(AF_INET6, &ip6h->daddr, buf_d, sizeof(buf_d))
		);
	} else {
		struct tcphdr *th = (struct tcphdr *)l4h;

		fprintf(stderr, "%s from tap: [%s]:%i\n"
				"\t-> [%s]:%i\n",
			getprotobynumber(proto)->p_name,
			inet_ntop(AF_INET6, &ip6h->saddr, buf_s, sizeof(buf_s)),
			ntohs(th->source),
			inet_ntop(AF_INET6, &ip6h->daddr, buf_d, sizeof(buf_d)),
			ntohs(th->dest));
	}

	len -= (intptr_t)l4h - (intptr_t)eh;

	if (proto == IPPROTO_TCP)
		tcp_tap_handler(c, AF_INET6, &ip6h->daddr, l4h, len);
	else if (proto == IPPROTO_UDP)
		udp_tap_handler(c, AF_INET6, &ip6h->daddr, l4h, len);
}

/**
 * tap_handler() - IPv4/IPv6/ARP packet handler for tap file descriptor
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @in:		Packet buffer, L2 headers
 */
static void tap_handler(struct ctx *c, char *in, size_t len)
{
	struct ethhdr *eh = (struct ethhdr *)in;

	if (eh->h_proto == ntohs(ETH_P_IP) || eh->h_proto == ntohs(ETH_P_ARP))
		tap4_handler(c, in, len);
	else if (eh->h_proto == ntohs(ETH_P_IPV6))
		tap6_handler(c, in, len);
}

/**
 * sock_handler() - Event handler for L4 sockets
 * @c:		Execution context
 * @fd:		File descriptor associated to event
 * @events	epoll events
 */
static void sock_handler(struct ctx *c, int fd, uint32_t events)
{
	socklen_t sl;
	int so;

	sl = sizeof(so);

	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &so, &sl) ||
	    so == SOCK_STREAM)
		tcp_sock_handler(c, fd, events);
	else if (so == SOCK_DGRAM)
		udp_sock_handler(c, fd, events);
}

/**
 * periodic_handler() - Run periodic tasks for L4 protocol handlers
 * @c:		Execution context
 * @last:	Timestamp of last run, updated on return
 */
static void periodic_handler(struct ctx *c, struct timespec *last)
{
	struct timespec tmp;
	int elapsed_ms;

	clock_gettime(CLOCK_MONOTONIC, &tmp);
	elapsed_ms = timespec_diff_ms(&tmp, last);

	if (elapsed_ms >= PERIODIC_HANDLER_FAST)
		tcp_periodic_fast(c);
	if (elapsed_ms >= PERIODIC_HANDLER_SLOW)
		tcp_periodic_slow(c);

	*last = tmp;
}

/**
 * usage() - Print usage and exit
 * @name:	Executable name
 */
void usage(const char *name)
{
	fprintf(stderr, "Usage: %s\n", name);

	exit(EXIT_FAILURE);
}

/**
 * main() - Entry point and main loop
 * @argc:	Argument count
 * @argv:	Interface names
 *
 * Return: 0 once interrupted, non-zero on failure
 */
int main(int argc, char **argv)
{
	char buf6[3][sizeof("0123:4567:89ab:cdef:0123:4567:89ab:cdef")];
	char buf4[4][sizeof("255.255.255.255")];
	struct epoll_event events[EPOLL_EVENTS];
	struct epoll_event ev = { 0 };
	struct timespec last_time;
	char buf[ETH_MAX_MTU];
	struct ctx c = { 0 };
	int nfds, i, len;
	int fd_unix;

	if (argc != 1)
		usage(argv[0]);

	get_routes(&c);
	get_addrs(&c);
	get_dns(&c);

	if (c.v4) {
		fprintf(stderr, "ARP:\n");
		fprintf(stderr, "\taddress: %02x:%02x:%02x:%02x:%02x:%02x "
			"from %s\n", c.mac[0], c.mac[1], c.mac[2],
				     c.mac[3], c.mac[4], c.mac[5], c.ifn);
		fprintf(stderr, "DHCP:\n");
		fprintf(stderr, "\tassign:\t%s\n\tnmask:\t%s\n"
				"\trouter:\t%s\n\tDNS:\t%s\n",
			inet_ntop(AF_INET, &c.addr4, buf4[0], sizeof(buf4[0])),
			inet_ntop(AF_INET, &c.mask4, buf4[1], sizeof(buf4[1])),
			inet_ntop(AF_INET, &c.gw4, buf4[2], sizeof(buf4[2])),
			inet_ntop(AF_INET, &c.dns4, buf4[3], sizeof(buf4[3])));
	}
	if (c.v6) {
		fprintf(stderr, "NDP:\n");
		fprintf(stderr, "\tassign:\t%s\n\trouter:\t%s\n\tDNS:\t%s\n",
			inet_ntop(AF_INET6, &c.addr6, buf6[0], sizeof(buf6[0])),
			inet_ntop(AF_INET6, &c.gw6, buf6[1], sizeof(buf6[1])),
			inet_ntop(AF_INET6, &c.dns6, buf6[2], sizeof(buf6[2])));
	}
	fprintf(stderr, "\n");

	if (clock_gettime(CLOCK_MONOTONIC, &last_time)) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}

	c.epollfd = epoll_create1(0);
	if (c.epollfd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	if (tcp_sock_init(&c) || udp_sock_init(&c))
		exit(EXIT_FAILURE);

	fd_unix = sock_unix();
listen:
	listen(fd_unix, 1);
	fprintf(stderr,
		"You can now start qrap:\n\t"
		"./qrap 5 kvm ... -net socket,fd=5 -net nic,model=virtio\n\n");

	c.fd_unix = accept(fd_unix, NULL, NULL);
	ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
	ev.data.fd = c.fd_unix;
	epoll_ctl(c.epollfd, EPOLL_CTL_ADD, c.fd_unix, &ev);

	clock_gettime(CLOCK_MONOTONIC, &last_time);

loop:
	nfds = epoll_wait(c.epollfd, events, EPOLL_EVENTS, EPOLL_TIMEOUT);
	if (nfds == -1 && errno != EINTR) {
		perror("epoll_wait");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < nfds; i++) {
		if (events[i].data.fd == c.fd_unix) {
			len = recv(events[i].data.fd, buf, sizeof(buf),
				   MSG_DONTWAIT);

			if (len <= 0) {
				epoll_ctl(c.epollfd, EPOLL_CTL_DEL, c.fd_unix,
					  &ev);
				close(c.fd_unix);
				goto listen;
			}

			if (len == 0 || (len < 0 && errno == EINTR))
				continue;

			if (len < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				goto out;
			}

			tap_handler(&c, buf + 4, ntohl(*(uint32_t *)buf));
		} else {
			sock_handler(&c, events[i].data.fd, events[i].events);
		}
	}

	periodic_handler(&c, &last_time);
	clock_gettime(CLOCK_MONOTONIC, &last_time);

	goto loop;

out:
	return 0;
}

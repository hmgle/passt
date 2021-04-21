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
#include <sys/resource.h>
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
#include <syslog.h>
#include <sys/stat.h>

#include "passt.h"
#include "arp.h"
#include "dhcp.h"
#include "ndp.h"
#include "dhcpv6.h"
#include "util.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

#define EPOLL_EVENTS		10

#define TIMER_INTERVAL		20 /* ms, for protocol periodic handlers */

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

	chmod(UNIX_SOCK_PATH,
	      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

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
		err("No routing information");
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
	err("Couldn't get addresses for routable interface");
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

	err("Couldn't get any nameserver address");
	exit(EXIT_FAILURE);
}

/**
 * tap4_handler() - IPv4 and ARP packet handler for tap file descriptor
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @in:		Packet buffer, L2 headers
 */
static void tap4_handler(struct ctx *c, char *in, size_t len)
{
	char buf_s[INET_ADDRSTRLEN] __attribute((__unused__));
	char buf_d[INET_ADDRSTRLEN] __attribute((__unused__));
	struct ethhdr *eh = (struct ethhdr *)in;
	struct iphdr *iph = (struct iphdr *)(eh + 1);
	char *l4h;

	if (!c->v4)
		return;

	if (arp(c, eh, len) || dhcp(c, eh, len))
		return;

	if (len < sizeof(*eh) + sizeof(*iph))
		return;

	l4h = (char *)iph + iph->ihl * 4;
	len -= (intptr_t)l4h - (intptr_t)eh;

	if (iph->protocol == IPPROTO_ICMP) {
		debug("icmp from tap: %s -> %s",
		      inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
		      inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)));
	} else {
		struct tcphdr *th = (struct tcphdr *)l4h;

		if (len < sizeof(*th) && len < sizeof(struct udphdr))
			return;

		debug("%s from tap: %s:%i -> %s:%i",
		      getprotobynumber(iph->protocol)->p_name,
		      inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
		      ntohs(th->source),
		      inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)),
		      ntohs(th->dest));
	}

	if (iph->protocol == IPPROTO_TCP)
		tcp_tap_handler(c, AF_INET, &iph->daddr, l4h, len);
	else if (iph->protocol == IPPROTO_UDP)
		udp_tap_handler(c, AF_INET, &iph->daddr, l4h, len);
	else if (iph->protocol == IPPROTO_ICMP)
		icmp_tap_handler(c, AF_INET, &iph->daddr, l4h, len);
}

/**
 * tap6_handler() - IPv6 packet handler for tap file descriptor
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @in:		Packet buffer, L2 headers
 */
static void tap6_handler(struct ctx *c, char *in, size_t len)
{
	char buf_s[INET6_ADDRSTRLEN] __attribute((__unused__));
	char buf_d[INET6_ADDRSTRLEN] __attribute((__unused__));
	struct ethhdr *eh = (struct ethhdr *)in;
	struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
	uint8_t proto;
	char *l4h;

	if (!c->v6)
		return;

	if (len < sizeof(*eh) + sizeof(*ip6h))
		return;

	if (ndp(c, eh, len) || dhcpv6(c, eh, len))
		return;

	l4h = ipv6_l4hdr(ip6h, &proto);

	c->addr6_guest = ip6h->saddr;
	ip6h->saddr = c->addr6;

	len -= (intptr_t)l4h - (intptr_t)eh;

	if (proto == IPPROTO_ICMPV6) {
		debug("icmpv6 from tap: %s ->\n\t%s",
		      inet_ntop(AF_INET6, &ip6h->saddr, buf_s, sizeof(buf_s)),
		      inet_ntop(AF_INET6, &ip6h->daddr, buf_d, sizeof(buf_d)));
	} else {
		struct tcphdr *th = (struct tcphdr *)l4h;

		if (len < sizeof(*th) && len < sizeof(struct udphdr))
			return;

		debug("%s from tap: [%s]:%i\n\t-> [%s]:%i",
		      getprotobynumber(proto)->p_name,
		      inet_ntop(AF_INET6, &ip6h->saddr, buf_s, sizeof(buf_s)),
		      ntohs(th->source),
		      inet_ntop(AF_INET6, &ip6h->daddr, buf_d, sizeof(buf_d)),
		      ntohs(th->dest));
	}

	if (proto == IPPROTO_TCP)
		tcp_tap_handler(c, AF_INET6, &ip6h->daddr, l4h, len);
	else if (proto == IPPROTO_UDP)
		udp_tap_handler(c, AF_INET6, &ip6h->daddr, l4h, len);
	else if (proto == IPPROTO_ICMPV6)
		icmp_tap_handler(c, AF_INET6, &ip6h->daddr, l4h, len);
}

/**
 * tap_handler() - Packet handler for tap file descriptor
 * @c:		Execution context
 *
 * Return: -ECONNRESET if tap connection was lost, 0 otherwise
 */
static int tap_handler(struct ctx *c)
{
	char buf[ETH_MAX_MTU];
	struct ethhdr *eh;
	uint32_t vnet_len;
	ssize_t n;

	eh = (struct ethhdr *)buf;

	while ((n = recv(c->fd_unix, &vnet_len, 4, MSG_DONTWAIT)) == 4) {
		n = recv(c->fd_unix, buf, ntohl(vnet_len), MSG_DONTWAIT);

		if (n < (ssize_t)sizeof(*eh))
			break;

		switch (ntohs(eh->h_proto)) {
		case ETH_P_IP:
		case ETH_P_ARP:
			tap4_handler(c, buf, n);
			break;
		case ETH_P_IPV6:
			tap6_handler(c, buf, n);
			break;
		default:
			break;
		}
	}

	if (n >= 0 || errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		return 0;

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_unix, NULL);
	close(c->fd_unix);

	return -ECONNRESET;
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

	if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &so, &sl))
		return;

	debug("%s: packet from socket %i", getprotobynumber(so)->p_name, fd);

	if (so == IPPROTO_ICMP || so == IPPROTO_ICMPV6)
		icmp_sock_handler(c, fd, events);
	else if (so == IPPROTO_TCP)
		tcp_sock_handler(c, fd, events);
	else if (so == IPPROTO_UDP)
		udp_sock_handler(c, fd, events);
}

/**
 * timer_handler() - Run periodic tasks for L4 protocol handlers
 * @c:		Execution context
 * @last:	Timestamp of last run, updated on return
 */
static void timer_handler(struct ctx *c, struct timespec *last)
{
	struct timespec tmp;

	clock_gettime(CLOCK_MONOTONIC, &tmp);
	if (timespec_diff_ms(&tmp, last) < TIMER_INTERVAL)
		return;

	tcp_timer(c, &tmp);

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
	struct epoll_event events[EPOLL_EVENTS];
	char buf6[3][INET6_ADDRSTRLEN];
	char buf4[4][INET_ADDRSTRLEN];
	struct epoll_event ev = { 0 };
	struct timespec last_time;
	struct ctx c = { 0 };
	int nfds, i, fd_unix;
	struct rlimit limit;

	if (argc != 1)
		usage(argv[0]);

	if (clock_gettime(CLOCK_MONOTONIC, &last_time)) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}

	c.epollfd = epoll_create1(0);
	if (c.epollfd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	if (getrlimit(RLIMIT_NOFILE, &limit)) {
		perror("getrlimit");
		exit(EXIT_FAILURE);
	}
	limit.rlim_cur = limit.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &limit)) {
		perror("setrlimit");
		exit(EXIT_FAILURE);
	}

#if DEBUG
	openlog("passt", LOG_PERROR, LOG_DAEMON);
#else
	openlog("passt", 0, LOG_DAEMON);
	if (daemon(0, 0)) {
		fprintf(stderr, "Failed to fork into background\n");
		exit(EXIT_FAILURE);
	}
#endif

	get_routes(&c);
	get_addrs(&c);
	get_dns(&c);

	fd_unix = sock_unix();

	if (icmp_sock_init(&c) || tcp_sock_init(&c) || udp_sock_init(&c))
		exit(EXIT_FAILURE);

	if (c.v6)
		dhcpv6_init(&c);

	if (c.v4) {
		info("ARP:");
		info("    address: %02x:%02x:%02x:%02x:%02x:%02x from %s",
		     c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5],
		     c.ifn);
		info("DHCP:");
		info("    assign: %s",
		     inet_ntop(AF_INET, &c.addr4, buf4[0], sizeof(buf4[0])));
		info("    mask: %s",
		     inet_ntop(AF_INET, &c.mask4, buf4[0], sizeof(buf4[0])));
		info("    router: %s",
		     inet_ntop(AF_INET, &c.gw4,   buf4[2], sizeof(buf4[2])));
		info("    DNS: %s",
		     inet_ntop(AF_INET, &c.dns4,  buf4[3], sizeof(buf4[3])));
	}
	if (c.v6) {
		info("NDP/DHCPv6:");
		info("    assign: %s",
		     inet_ntop(AF_INET6, &c.addr6, buf6[0], sizeof(buf6[0])));
		info("    router: %s",
		     inet_ntop(AF_INET6, &c.gw6,   buf6[1], sizeof(buf6[1])));
		info("    DNS: %s",
		     inet_ntop(AF_INET6, &c.dns6,  buf6[2], sizeof(buf6[2])));
	}

listen:
	listen(fd_unix, 1);
	info("You can now start qrap:");
	info("    ./qrap 5 kvm ... -net socket,fd=5 -net nic,model=virtio");
	info("or directly qemu, patched with:");
	info("    qemu/0001-net-Allow-also-UNIX-domain-sockets-to-be-used-as-net.patch");
	info("as follows:");
	info("    kvm ... -net socket,connect="
	     UNIX_SOCK_PATH " -net nic,model=virtio");

	c.fd_unix = accept(fd_unix, NULL, NULL);
	ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
	ev.data.fd = c.fd_unix;
	epoll_ctl(c.epollfd, EPOLL_CTL_ADD, c.fd_unix, &ev);

	clock_gettime(CLOCK_MONOTONIC, &last_time);

loop:
	nfds = epoll_wait(c.epollfd, events, EPOLL_EVENTS, TIMER_INTERVAL);
	if (nfds == -1 && errno != EINTR) {
		perror("epoll_wait");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < nfds; i++) {
		if (events[i].data.fd == c.fd_unix) {
			if (tap_handler(&c))
				goto listen;
		} else {
			sock_handler(&c, events[i].data.fd, events[i].events);
		}
	}

	timer_handler(&c, &last_time);

	goto loop;

	return 0;
}

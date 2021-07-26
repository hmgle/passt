// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * passt.c - Daemon implementation
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * Grab Ethernet frames from AF_UNIX socket (in "passt" mode) or tap device (in
 * "pasta" mode), build SOCK_DGRAM/SOCK_STREAM sockets for each 5-tuple from
 * TCP, UDP packets, perform connection tracking and forward them. Forward
 * packets received on sockets back to the UNIX domain socket (typically, a
 * socket virtio_net file descriptor from qemu) or to the tap device (typically,
 * created in a separate network namespace).
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/un.h>
#include <linux/if_link.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>

#include "util.h"
#include "passt.h"
#include "dhcpv6.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "pcap.h"
#include "tap.h"

#define EPOLL_EVENTS		10

#define __TIMER_INTERVAL	MIN(TCP_TIMER_INTERVAL, UDP_TIMER_INTERVAL)
#define TIMER_INTERVAL		MIN(__TIMER_INTERVAL, ICMP_TIMER_INTERVAL)

char pkt_buf			[PKT_BUF_BYTES];

#ifdef DEBUG
char *ip_proto_str[IPPROTO_SCTP + 1] = {
	[IPPROTO_ICMP]		= "ICMP",
	[IPPROTO_TCP]		= "TCP",
	[IPPROTO_UDP]		= "UDP",
	[IPPROTO_ICMPV6]	= "ICMPV6",
	[IPPROTO_SCTP]		= "SCTP",
};
#endif

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
			c->addr4_seen = c->addr4 = in_addr->sin_addr.s_addr;
			in_addr = (struct sockaddr_in *)ifa->ifa_netmask;
			c->mask4 = in_addr->sin_addr.s_addr;
			v4 = 1;
		} else if (ifa->ifa_addr->sa_family == AF_INET6 && !v6) {
			in6_addr = (struct sockaddr_in6 *)ifa->ifa_addr;
			memcpy(&c->addr6, &in6_addr->sin6_addr,
			       sizeof(c->addr6));
			memcpy(&c->addr6_seen, &in6_addr->sin6_addr,
			       sizeof(c->addr6_seen));
			memcpy(&c->addr6_ll_seen, &in6_addr->sin6_addr,
			       sizeof(c->addr6_seen));
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
	struct in6_addr *dns6 = &c->dns6[0];
	struct fqdn *s = c->dns_search;
	uint32_t *dns4 = &c->dns4[0];
	char buf[BUFSIZ], *p, *end;
	FILE *r;

	r = fopen("/etc/resolv.conf", "r");
	while (fgets(buf, BUFSIZ, r)) {
		if (strstr(buf, "nameserver ") == buf) {
			p = strrchr(buf, ' ');
			if (!p)
				continue;

			end = strpbrk(buf, "%\n");
			if (end)
				*end = 0;

			if (dns4 - &c->dns4[0] < ARRAY_SIZE(c->dns4) &&
			    inet_pton(AF_INET, p + 1, dns4))
				dns4++;

			if (dns6 - &c->dns6[0] < ARRAY_SIZE(c->dns6) &&
			    inet_pton(AF_INET6, p + 1, dns6))
				dns6++;
		} else if (strstr(buf, "search ") == buf &&
			   s == c->dns_search) {
			end = strpbrk(buf, "\n");
			if (end)
				*end = 0;

			p = strtok(buf, " \t");
			while ((p = strtok(NULL, " \t")) &&
			       s - c->dns_search < ARRAY_SIZE(c->dns_search)) {
				strncpy(s->n, p, sizeof(c->dns_search[0]));
				s++;
			}
		}
	}

	fclose(r);

	if (dns4 == c->dns4 && dns6 == c->dns6)
		warn("Couldn't get any nameserver address");
}

/**
 * get_bound_ports_ns() - Get TCP and UDP ports bound in namespace
 * @arg:	Execution context
 *
 * Return: 0
 */
static int get_bound_ports_ns(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	ns_enter(c->pasta_pid);

	if (c->v4) {
		procfs_scan_listen("tcp", c->tcp.port4_to_tap);
		procfs_scan_listen("tcp", c->udp.port4_to_tap);
		procfs_scan_listen("udp", c->udp.port4_to_tap);

		procfs_scan_listen("tcp", c->tcp.port4_to_ns);
		procfs_scan_listen("tcp", c->udp.port4_to_ns);
		procfs_scan_listen("udp", c->udp.port4_to_ns);
	}

	if (c->v6) {
		if (c->v4) {
			procfs_scan_listen("tcp6", c->tcp.port4_to_tap);
			procfs_scan_listen("tcp6", c->udp.port4_to_tap);
			procfs_scan_listen("udp6", c->udp.port4_to_tap);

			procfs_scan_listen("tcp6", c->tcp.port4_to_ns);
			procfs_scan_listen("tcp6", c->udp.port4_to_ns);
			procfs_scan_listen("udp6", c->udp.port4_to_ns);
		}

		procfs_scan_listen("tcp6", c->tcp.port6_to_tap);
		procfs_scan_listen("tcp6", c->udp.port6_to_tap);
		procfs_scan_listen("udp6", c->udp.port6_to_tap);

		procfs_scan_listen("tcp6", c->tcp.port6_to_ns);
		procfs_scan_listen("tcp6", c->udp.port6_to_ns);
		procfs_scan_listen("udp6", c->udp.port6_to_ns);
	}

	return 0;
}

/**
 * get_bound_ports() - Get maps of ports that should have bound sockets
 * @c:		Execution context
 */
static void get_bound_ports(struct ctx *c)
{
	char ns_fn_stack[NS_FN_STACK_SIZE];

	clone(get_bound_ports_ns, ns_fn_stack + sizeof(ns_fn_stack) / 2,
	      CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD, (void *)c);

	if (c->v4) {
		procfs_scan_listen("tcp", c->tcp.port4_to_init);
		procfs_scan_listen("tcp", c->udp.port4_to_init);
		procfs_scan_listen("udp", c->udp.port4_to_init);
	}

	if (c->v6) {
		if (c->v4) {
			procfs_scan_listen("tcp6", c->tcp.port4_to_init);
			procfs_scan_listen("tcp6", c->udp.port4_to_init);
			procfs_scan_listen("udp6", c->udp.port4_to_init);
		}

		procfs_scan_listen("tcp6", c->tcp.port6_to_init);
		procfs_scan_listen("tcp6", c->udp.port6_to_init);
		procfs_scan_listen("udp6", c->udp.port6_to_init);

	}
}

/**
 * sock_handler() - Event handler for L4 sockets
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events
 * @now:	Current timestamp
 */
static void sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
			 struct timespec *now)
{
	debug("%s packet from socket %i", IP_PROTO_STR(ref.proto), ref.s);

	if (ref.proto == IPPROTO_TCP)
		tcp_sock_handler( c, ref, events, now);
	else if (ref.proto == IPPROTO_UDP)
		udp_sock_handler( c, ref, events, now);
	else if (ref.proto == IPPROTO_ICMP || ref.proto == IPPROTO_ICMPV6)
		icmp_sock_handler(c, ref, events, now);
}

/**
 * timer_handler() - Run periodic tasks for L4 protocol handlers
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void timer_handler(struct ctx *c, struct timespec *now)
{
	if (timespec_diff_ms(now, &c->tcp.timer_run) >= TCP_TIMER_INTERVAL) {
		tcp_timer(c, now);
		c->tcp.timer_run = *now;
	}

	if (timespec_diff_ms(now, &c->udp.timer_run) >= UDP_TIMER_INTERVAL) {
		udp_timer(c, now);
		c->udp.timer_run = *now;
	}

	if (timespec_diff_ms(now, &c->icmp.timer_run) >= ICMP_TIMER_INTERVAL) {
		icmp_timer(c, now);
		c->icmp.timer_run = *now;
	}
}

/**
 * proto_update_l2_buf() - Update scatter-gather L2 buffers in protocol handlers
 * @eth_d:	Ethernet destination address, NULL if unchanged
 * @eth_s:	Ethernet source address, NULL if unchanged
 * @ip_da:	Pointer to IPv4 destination address, NULL if unchanged
 */
void proto_update_l2_buf(unsigned char *eth_d, unsigned char *eth_s,
			 uint32_t *ip_da)
{
	udp_update_l2_buf(eth_d, eth_s, ip_da);
}

/**
 * usage_passt() - Print usage for "passt" mode and exit
 * @name:	Executable name
 */
void usage_passt(const char *name)
{
	fprintf(stderr, "Usage: %s\n", name);

	exit(EXIT_FAILURE);
}

/**
 * usage_pasta() - Print usage for "pasta" mode and exit
 * @name:	Executable name
 */
void usage_pasta(const char *name)
{
	fprintf(stderr, "Usage: %s TARGET_PID\n", name);

	exit(EXIT_FAILURE);
}

/**
 * main() - Entry point and main loop
 * @argc:	Argument count
 * @argv:	Target PID for pasta mode
 *
 * Return: 0 once interrupted, non-zero on failure
 */
int main(int argc, char **argv)
{
	char buf6[INET6_ADDRSTRLEN], buf4[INET_ADDRSTRLEN], *log_name;
	struct epoll_event events[EPOLL_EVENTS];
	struct ctx c = { 0 };
	struct rlimit limit;
	struct timespec now;
	int nfds, i;

	if (strstr(argv[0], "pasta") || strstr(argv[0], "passt4netns")) {
		if (argc != 2)
			usage_pasta(argv[0]);

		errno = 0;
		c.pasta_pid = strtol(argv[1], NULL, 0);
		if (c.pasta_pid < 0 || errno)
			usage_pasta(argv[0]);

		c.mode = MODE_PASTA;
		log_name = "pasta";
	} else {
		if (argc != 1)
			usage_passt(argv[0]);

		c.mode = MODE_PASST;
		log_name = "passt";
		memset(&c.mac_guest, 0xff, sizeof(c.mac_guest));
	}

	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
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
	openlog(log_name, 0, LOG_DAEMON);
#else
	openlog(log_name, isatty(fileno(stdout)) ? 0 : LOG_PERROR, LOG_DAEMON);
#endif

	get_routes(&c);
	get_addrs(&c);
	get_dns(&c);

	if (c.mode == MODE_PASST) {
		memset(&c.tcp.port4_to_tap, 0xff, PORT_EPHEMERAL_MIN / 8);
		memset(&c.tcp.port6_to_tap, 0xff, PORT_EPHEMERAL_MIN / 8);
		memset(&c.udp.port4_to_tap, 0xff, PORT_EPHEMERAL_MIN / 8);
		memset(&c.udp.port6_to_tap, 0xff, PORT_EPHEMERAL_MIN / 8);
	} else {
		get_bound_ports(&c);
	}

	proto_update_l2_buf(c.mac_guest, c.mac, &c.addr4);

	if (udp_sock_init(&c) || tcp_sock_init(&c))
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
		     inet_ntop(AF_INET, &c.addr4,  buf4, sizeof(buf4)));
		info("    mask: %s",
		     inet_ntop(AF_INET, &c.mask4,  buf4, sizeof(buf4)));
		info("    router: %s",
		     inet_ntop(AF_INET, &c.gw4,    buf4, sizeof(buf4)));
		for (i = 0; c.dns4[i]; i++) {
			if (!i)
				info("    DNS:");
			inet_ntop(AF_INET, &c.dns4[i], buf4, sizeof(buf4));
			info("        %s", buf4);
		}
		for (i = 0; *c.dns_search[i].n; i++) {
			if (!i)
				info("        search:");
			info("            %s", c.dns_search[i].n);
		}
	}
	if (c.v6) {
		info("NDP/DHCPv6:");
		info("    assign: %s",
		     inet_ntop(AF_INET6, &c.addr6, buf6, sizeof(buf6)));
		info("    router: %s",
		     inet_ntop(AF_INET6, &c.gw6,   buf6, sizeof(buf6)));
		for (i = 0; !IN6_IS_ADDR_UNSPECIFIED(&c.dns6[i]); i++) {
			if (!i)
				info("    DNS:");
			inet_ntop(AF_INET6, &c.dns6[i], buf6, sizeof(buf6));
			info("        %s", buf6);
		}
		for (i = 0; *c.dns_search[i].n; i++) {
			if (!i)
				info("        search:");
			info("            %s", c.dns_search[i].n);
		}
	}

	tap_sock_init(&c);

#ifndef DEBUG
	if (isatty(fileno(stdout)) && daemon(0, 0)) {
		fprintf(stderr, "Failed to fork into background\n");
		exit(EXIT_FAILURE);
	}
#endif

loop:
	nfds = epoll_wait(c.epollfd, events, EPOLL_EVENTS, TIMER_INTERVAL);
	if (nfds == -1 && errno != EINTR) {
		perror("epoll_wait");
		exit(EXIT_FAILURE);
	}

	clock_gettime(CLOCK_MONOTONIC, &now);

	for (i = 0; i < nfds; i++) {
		union epoll_ref ref = *((union epoll_ref *)&events[i].data.u64);

		if (events[i].data.fd == c.fd_tap)
			tap_handler(&c, events[i].events, &now);
		else
			sock_handler(&c, ref, events[i].events, &now);
	}

	timer_handler(&c, &now);

	goto loop;

	return 0;
}

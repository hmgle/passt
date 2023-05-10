/* SPDX-License-Identifier: GPL-2.0-or-later
 * Author: Hmgle <dustgle@gmail.com>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "log.h"
#include <strings.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/route.h>

#include "util.h"
#include "passt.h"
#include "pasta.h"
#include "child.h"

static int up_network_interface(char *interface_name) {
	int sockfd;
	struct ifreq ifr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
	strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
#pragma GCC diagnostic pop

	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		perror("ioctl(SIOCGIFFLAGS)");
		return -1;
	}

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl(SIOCSIFFLAGS)");
		return -1;
	}

	return 0;
}

static int set_ip4(const char *interface, const char *ip4_addr, const char *mask)
{
	int fd;
	struct ifreq ifr;
	struct sockaddr_in* addr;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_addr.sa_family = AF_INET;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
#pragma GCC diagnostic pop

	addr = (struct sockaddr_in*)&ifr.ifr_addr;
	if (inet_pton(AF_INET, ip4_addr, &addr->sin_addr) != 1) {
		warn("%s is not a valid IPv4 network address", ip4_addr);
		ret = EXIT_FAILURE;
		goto end;
	}
	ret = ioctl(fd, SIOCSIFADDR, &ifr);
	if (ret) {
		perror("SIOCSIFADDR");
		goto end;
	}

	if (inet_pton(AF_INET, mask, &addr->sin_addr) != 1) {
		warn("%s is not a valid IPv4 network address", mask);
		ret = EXIT_FAILURE;
		goto end;
	}
	ret = ioctl(fd, SIOCSIFNETMASK, &ifr);
	if (ret)
		perror("SIOCSIFNETMASK");

end:
	close(fd);
	return ret;
}

struct in6_ifreq {
	struct in6_addr	ifr6_addr;
	uint32_t	ifr6_prefixlen;
	int		ifr6_ifindex;
};

static int set_ip6(const char *interface, const char *ip6_addr)
{
	int fd;
	struct ifreq ifr;
	struct in6_ifreq ifr6;
	int ret;

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	memset(&ifr, 0, sizeof(struct ifreq));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
#pragma GCC diagnostic pop

	ret = ioctl(fd, SIOGIFINDEX, &ifr);
	if (ret) {
		perror("SIOGIFINDEX");
		goto end;
	}

	if (inet_pton(AF_INET6, ip6_addr, &ifr6.ifr6_addr) != 1) {
		warn("%s is not a valid IPv6 network address", ip6_addr);
		ret = EXIT_FAILURE;
		goto end;
	}
	ifr6.ifr6_ifindex = ifr.ifr_ifindex;
	ifr6.ifr6_prefixlen = 64;
	ret = ioctl(fd, SIOCSIFADDR, &ifr6);
	if (ret)
		perror("SIOCSIFADDR");

end:
	close(fd);
	return ret;
}


static int add_routing_table(char *interface, const char *ip4_addr)
{
	int sockfd;
	struct rtentry rt;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("socket");
		return -1;
	}

	memset(&rt, 0, sizeof(rt));
	struct sockaddr_in *sockinfo = (struct sockaddr_in *)&rt.rt_gateway;
	sockinfo->sin_family = AF_INET;
	sockinfo->sin_addr.s_addr = inet_addr(ip4_addr);

	sockinfo = (struct sockaddr_in *)&rt.rt_dst;
	sockinfo->sin_family = AF_INET;
	sockinfo->sin_addr.s_addr = INADDR_ANY;

	sockinfo = (struct sockaddr_in *)&rt.rt_genmask;
	sockinfo->sin_family = AF_INET;
	sockinfo->sin_addr.s_addr = INADDR_ANY;

	rt.rt_flags = RTF_UP | RTF_GATEWAY;
	rt.rt_dev = interface;

	if (ioctl(sockfd, SIOCADDRT, &rt) < 0)
		perror("ioctl");
	close(sockfd);
	return 0;
}

static int add_routing_ip6_table(const char *interface_name, const char *ip6_addr) {
	int sockfd;
	struct in6_rtmsg route;
	struct sockaddr_in6 *addr;
	int ret;

	memset(&route, 0, sizeof(route));

	// Set gateway address
	addr = (struct sockaddr_in6 *)&route.rtmsg_gateway;
	addr->sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, ip6_addr, &addr->sin6_addr) != 1) {
		warn("%s is not a valid IPv6 network address", ip6_addr);
		return EXIT_FAILURE;
	}

	// Set prefix length
	route.rtmsg_dst_len = 64;

	memset(&addr->sin6_addr, 0, sizeof(addr->sin6_addr));

	route.rtmsg_flags = RTF_UP;
	route.rtmsg_ifindex = if_nametoindex(interface_name);

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	ret = ioctl(sockfd, SIOCADDRT, &route);
	if (ret < 0)
		perror("ioctl(SIOCADDRT)");
	close(sockfd);
	return ret;
}


static void do_child(int argc, char **argv)
{
	char *args[argc + 1];
	int i;

	for (i = 0; i < argc; i++)
		args[i] = argv[i];
	args[argc] = NULL;

	execvp(args[0], args);
	perror("execvp");
	exit(EXIT_FAILURE);
}

pid_t pasta_start_child(struct ctx *c, uid_t uid, gid_t gid, int argc, char **argv)
{
	pid_t ch_pid;
	sigset_t set, oldset;
	sigprocmask(SIG_SETMASK, NULL, &oldset);
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, NULL);

	ch_pid = fork();
	if (ch_pid == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else if (ch_pid == 0) {
		if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == -1) {
			perror("unshare1");
			exit(EXIT_FAILURE);
		}

		char *uidmap = NULL;
		char *gidmap = NULL;

		if (asprintf(&uidmap, "0 %u 1", uid) < 0 ||
		    asprintf(&gidmap, "0 %u 1", gid) < 0) {
			perror("asprintf");
			exit(EXIT_FAILURE);
		}

		if (write_file("/proc/self/uid_map", uidmap) ||
		    write_file("/proc/self/setgroups", "deny") ||
		    write_file("/proc/self/gid_map", gidmap)) {
			warn("Couldn't configure user mappings");
			exit(EXIT_FAILURE);
		}

		kill(getppid(), SIGUSR1);

		/* Wait for the parent to be ready: see main() */
		sigprocmask(SIG_SETMASK, NULL, &oldset);
		sigwaitinfo(&set, NULL);
		sigprocmask(SIG_SETMASK, &oldset, NULL);

		/* network config */
		if (up_network_interface(c->pasta_ifn) < 0)
			exit(EXIT_FAILURE);

		char ipaddrbuf[INET_ADDRSTRLEN], maskbuf[INET_ADDRSTRLEN];
		char routerbuf[INET_ADDRSTRLEN];
		uint32_t mask = htonl(0xffffffff << (32 - c->ip4.prefix_len));

		if (c->ifi4) {
			inet_ntop(AF_INET, &c->ip4.addr, ipaddrbuf, sizeof(ipaddrbuf));
			inet_ntop(AF_INET, &mask, maskbuf, sizeof(maskbuf));
			inet_ntop(AF_INET, &c->ip4.gw, routerbuf, sizeof(routerbuf));

			if (set_ip4(c->pasta_ifn, ipaddrbuf, maskbuf))
				exit(EXIT_FAILURE);
			if (add_routing_table(c->pasta_ifn, routerbuf))
				exit(EXIT_FAILURE);
		}
		if (c->ifi6) {
			inet_ntop(AF_INET, &c->ip6.addr, ipaddrbuf, sizeof(ipaddrbuf));
			inet_ntop(AF_INET, &c->ip6.gw, routerbuf, sizeof(routerbuf));

			if (set_ip6(c->pasta_ifn, ipaddrbuf))
				exit(EXIT_FAILURE);
			if (add_routing_ip6_table(c->pasta_ifn, routerbuf))
				exit(EXIT_FAILURE);
		}

		if (write_file("/proc/sys/net/ipv4/ping_group_range", "0 0"))
			warn("Cannot set ping_group_range, ICMP requests might fail");

		if (unshare(CLONE_NEWUSER) == -1) {
			perror("unshare2");
			exit(EXIT_FAILURE);
		}

		sprintf(uidmap, "%u 0 1", uid);
		sprintf(gidmap, "%u 0 1", gid);
		if (write_file("/proc/self/uid_map", uidmap) ||
		    write_file("/proc/self/setgroups", "deny") ||
		    write_file("/proc/self/gid_map", gidmap)) {
			warn("Couldn't configure user mappings");
			exit(EXIT_FAILURE);
		}
		free(uidmap);
		free(gidmap);

		do_child(argc, argv);
	}
	pasta_child_pid = ch_pid;
	sigwaitinfo(&set, NULL);
	sigprocmask(SIG_SETMASK, &oldset, NULL);
	return ch_pid;
}

/* SPDX-License-Identifier: GPL-2.0-or-later
 * Author: Hmgle <dustgle@gmail.com>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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
	strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);

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

static int set_ip(const char *interface, const char *ip_address, const char *mask)
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
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, interface);

	addr = (struct sockaddr_in*)&ifr.ifr_addr;
	inet_pton(AF_INET, ip_address, &addr->sin_addr);
	ret = ioctl(fd, SIOCSIFADDR, &ifr);
	if (ret) {
		perror("SIOCSIFADDR");
		goto end;
	}

	inet_pton(AF_INET, mask, &addr->sin_addr);
	ret = ioctl(fd, SIOCSIFNETMASK, &ifr);
	if (ret) {
		perror("SIOCSIFNETMASK");
	}
end:
	close(fd);
	return ret;
}

static int add_routing_table(char *interface, const char *ip_address)
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
	sockinfo->sin_addr.s_addr = inet_addr(ip_address);

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
		char ifnbuf[IFNAMSIZ];
		char ipaddrbuf[INET_ADDRSTRLEN], maskbuf[INET_ADDRSTRLEN];
		char routerbuf[INET_ADDRSTRLEN];
		uint32_t mask = htonl(0xffffffff << (32 - c->ip4.prefix_len));

		if_indextoname(c->ifi4, ifnbuf);
		inet_ntop(AF_INET, &c->ip4.addr, ipaddrbuf, sizeof(ipaddrbuf));
		inet_ntop(AF_INET, &mask, maskbuf, sizeof(maskbuf));
		inet_ntop(AF_INET, &c->ip4.gw, routerbuf, sizeof(routerbuf));

		if (up_network_interface(ifnbuf) < 0)
			exit(EXIT_FAILURE);
		if (set_ip(ifnbuf, ipaddrbuf, maskbuf))
			exit(EXIT_FAILURE);
		if (add_routing_table(ifnbuf, routerbuf))
			exit(EXIT_FAILURE);

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

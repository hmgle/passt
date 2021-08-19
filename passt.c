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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
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
#include "conf.h"

#define EPOLL_EVENTS		10

#define __TIMER_INTERVAL	MIN(TCP_TIMER_INTERVAL, UDP_TIMER_INTERVAL)
#define TIMER_INTERVAL		MIN(__TIMER_INTERVAL, ICMP_TIMER_INTERVAL)

char pkt_buf			[PKT_BUF_BYTES];

char *ip_proto_str[IPPROTO_SCTP + 1] = {
	[IPPROTO_ICMP]		= "ICMP",
	[IPPROTO_TCP]		= "TCP",
	[IPPROTO_UDP]		= "UDP",
	[IPPROTO_ICMPV6]	= "ICMPV6",
	[IPPROTO_SCTP]		= "SCTP",
};

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

	if (!c->no_tcp && ref.proto == IPPROTO_TCP)
		tcp_sock_handler( c, ref, events, now);
	else if (!c->no_udp && ref.proto == IPPROTO_UDP)
		udp_sock_handler( c, ref, events, now);
	else if (!c->no_icmp &&
		 (ref.proto == IPPROTO_ICMP || ref.proto == IPPROTO_ICMPV6))
		icmp_sock_handler(c, ref, events, now);
}

/**
 * timer_handler() - Run periodic tasks for L4 protocol handlers
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void timer_handler(struct ctx *c, struct timespec *now)
{
	if (!c->no_tcp &&
	    timespec_diff_ms(now, &c->tcp.timer_run) >= TCP_TIMER_INTERVAL) {
		tcp_timer(c, now);
		c->tcp.timer_run = *now;
	}

	if (!c->no_udp &&
	    timespec_diff_ms(now, &c->udp.timer_run) >= UDP_TIMER_INTERVAL) {
		udp_timer(c, now);
		c->udp.timer_run = *now;
	}

	if (!c->no_icmp &&
	    timespec_diff_ms(now, &c->icmp.timer_run) >= ICMP_TIMER_INTERVAL) {
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
	tcp_update_l2_buf(eth_d, eth_s, ip_da);
	udp_update_l2_buf(eth_d, eth_s, ip_da);
}

static int pasta_child_pid;

/**
 * pasta_child_handler() - Exit once shell spawned by pasta_start_ns() exits
 * @signal:	Unused, handler deals with SIGCHLD only
 */
static void pasta_child_handler(int signal)
{
	siginfo_t infop;

	(void)signal;

	if (!waitid(P_PID, pasta_child_pid, &infop, WEXITED | WNOHANG)) {
		if (infop.si_pid == pasta_child_pid)
			exit(EXIT_SUCCESS);
	}
}

/**
 * pasta_wait_for_ns() - Busy loop until we can enter the target namespace
 * @target_pid:	PID of process associated with target namespace
 *
 * Return: 0
 */
static int pasta_wait_for_ns(void *target_pid)
{
	while (ns_enter(*(int *)target_pid));
	return 0;
}

/**
 * pasta_start_ns() - Fork shell in new namespace if target PID is not given
 * @c:		Execution context
 */
static void pasta_start_ns(struct ctx *c)
{
	char buf[BUFSIZ], *shell;
	int euid = geteuid();
	struct sigaction sa;
	int fd;

	c->foreground = 1;
	if (!c->debug)
		c->quiet = 1;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = pasta_child_handler;
	sigaction(SIGCHLD, &sa, NULL);

	if ((c->pasta_pid = fork()) == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if ((pasta_child_pid = c->pasta_pid)) {
		NS_CALL(pasta_wait_for_ns, &pasta_child_pid);
		return;
	}

	if (unshare(CLONE_NEWNET | CLONE_NEWUSER)) {
		perror("unshare");
		exit(EXIT_FAILURE);
	}

	snprintf(buf, BUFSIZ, "%u %u %u", 0, euid, 1);

	fd = open("/proc/self/uid_map", O_WRONLY);
	write(fd, buf, strlen(buf));
	close(fd);

	fd = open("/proc/self/setgroups", O_WRONLY);
	write(fd, "deny", sizeof("deny"));
	close(fd);

	fd = open("/proc/self/gid_map", O_WRONLY);
	write(fd, buf, strlen(buf));
	close(fd);

	shell = getenv("SHELL") ? getenv("SHELL") : "/bin/sh";
	if (strstr(shell, "/bash"))
		execve(shell, ((char *[]) { shell, "-l", NULL }), environ);
	else
		execve(shell, ((char *[]) { shell, NULL }), environ);

	perror("execve");
	exit(EXIT_FAILURE);
}

/**
 * main() - Entry point and main loop
 * @argc:	Argument count
 * @argv:	Options, plus optional target PID for pasta mode
 *
 * Return: 0 once interrupted, non-zero on failure
 */
int main(int argc, char **argv)
{
	struct epoll_event events[EPOLL_EVENTS];
	struct ctx c = { 0 };
	struct rlimit limit;
	struct timespec now;
	char *log_name;
	int nfds, i;

	if (strstr(argv[0], "pasta") || strstr(argv[0], "passt4netns")) {
		c.mode = MODE_PASTA;
		log_name = "pasta";
	} else {
		c.mode = MODE_PASST;
		log_name = "passt";
	}

	openlog(log_name, 0, LOG_DAEMON);

	setlogmask(LOG_MASK(LOG_EMERG));
	conf(&c, argc, argv);

	if (!c.debug && (c.stderr || isatty(fileno(stdout))))
		openlog(log_name, LOG_PERROR, LOG_DAEMON);

	if (c.mode == MODE_PASTA && !c.pasta_pid)
		pasta_start_ns(&c);

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

	proto_update_l2_buf(c.mac_guest, c.mac, &c.addr4);

	tap_sock_init(&c);

	if ((!c.no_udp && udp_sock_init(&c)) ||
	    (!c.no_tcp && tcp_sock_init(&c)))
		exit(EXIT_FAILURE);

	if (c.v6 && !c.no_dhcpv6)
		dhcpv6_init(&c);

	if (c.debug)
		setlogmask(LOG_UPTO(LOG_DEBUG));
	else if (c.quiet)
		setlogmask(LOG_UPTO(LOG_ERR));
	else
		setlogmask(LOG_UPTO(LOG_INFO));

	if (isatty(fileno(stdout)) && !c.foreground)
		daemon(0, 0);
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

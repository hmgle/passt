// SPDX-License-Identifier: GPL-2.0-or-later

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

#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <netinet/if_ether.h>

#include "util.h"
#include "passt.h"
#include "dhcp.h"
#include "dhcpv6.h"
#include "isolation.h"
#include "pcap.h"
#include "tap.h"
#include "conf.h"
#include "pasta.h"
#include "arch.h"
#include "log.h"

#define EPOLL_EVENTS		8

#define __TIMER_INTERVAL	MIN(TCP_TIMER_INTERVAL, UDP_TIMER_INTERVAL)
#define TIMER_INTERVAL		MIN(__TIMER_INTERVAL, ICMP_TIMER_INTERVAL)

char pkt_buf[PKT_BUF_BYTES]	__attribute__ ((aligned(PAGE_SIZE)));

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
static void sock_handler(struct ctx *c, union epoll_ref ref,
			 uint32_t events, const struct timespec *now)
{
	trace("%s: %s packet from socket %i (events: 0x%08x)",
	      c->mode == MODE_PASST ? "passt" : "pasta",
	      IP_PROTO_STR(ref.r.proto), ref.r.s, events);

	if (!c->no_tcp && ref.r.proto == IPPROTO_TCP)
		tcp_sock_handler( c, ref, events, now);
	else if (!c->no_udp && ref.r.proto == IPPROTO_UDP)
		udp_sock_handler( c, ref, events, now);
	else if (!c->no_icmp &&
		 (ref.r.proto == IPPROTO_ICMP || ref.r.proto == IPPROTO_ICMPV6))
		icmp_sock_handler(c, ref, events, now);
}

/**
 * post_handler() - Run periodic and deferred tasks for L4 protocol handlers
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void post_handler(struct ctx *c, const struct timespec *now)
{
#define CALL_PROTO_HANDLER(c, now, lc, uc)				\
	do {								\
		extern void						\
		lc ## _defer_handler (struct ctx *c)			\
		__attribute__ ((weak));					\
									\
		if (!c->no_ ## lc) {					\
			if (lc ## _defer_handler)			\
				lc ## _defer_handler(c);		\
									\
			if (timespec_diff_ms((now), &c->lc.timer_run)	\
			    >= uc ## _TIMER_INTERVAL) {			\
				lc ## _timer(c, now);			\
				c->lc.timer_run = *now;			\
			}						\
		} 							\
	} while (0)

	/* NOLINTNEXTLINE(bugprone-branch-clone): intervals can be the same */
	CALL_PROTO_HANDLER(c, now, tcp, TCP);
	/* NOLINTNEXTLINE(bugprone-branch-clone): intervals can be the same */
	CALL_PROTO_HANDLER(c, now, udp, UDP);
	/* NOLINTNEXTLINE(bugprone-branch-clone): intervals can be the same */
	CALL_PROTO_HANDLER(c, now, icmp, ICMP);

#undef CALL_PROTO_HANDLER
}

/**
 * timer_init() - Set initial timestamp for timer runs to current time
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void timer_init(struct ctx *c, const struct timespec *now)
{
	c->tcp.timer_run = c->udp.timer_run = c->icmp.timer_run = *now;
}

/**
 * proto_update_l2_buf() - Update scatter-gather L2 buffers in protocol handlers
 * @eth_d:	Ethernet destination address, NULL if unchanged
 * @eth_s:	Ethernet source address, NULL if unchanged
 * @ip_da:	Pointer to IPv4 destination address, NULL if unchanged
 */
void proto_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s,
			 const struct in_addr *ip_da)
{
	tcp_update_l2_buf(eth_d, eth_s, ip_da);
	udp_update_l2_buf(eth_d, eth_s, ip_da);
}

/**
 * exit_handler() - Signal handler for SIGQUIT and SIGTERM
 * @unused:	Unused, handler deals with SIGQUIT and SIGTERM only
 *
 * TODO: After unsharing the PID namespace and forking, SIG_DFL for SIGTERM and
 * SIGQUIT unexpectedly doesn't cause the process to terminate, figure out why.
 *
 * #syscalls exit_group
 */
void exit_handler(int signal)
{
	(void)signal;

	exit(EXIT_SUCCESS);
}

/**
 * main() - Entry point and main loop
 * @argc:	Argument count
 * @argv:	Options, plus optional target PID for pasta mode
 *
 * Return: non-zero on failure
 *
 * #syscalls read write writev
 * #syscalls socket bind connect getsockopt setsockopt s390x:socketcall close
 * #syscalls recvfrom sendto shutdown
 * #syscalls armv6l:recv armv7l:recv ppc64le:recv
 * #syscalls armv6l:send armv7l:send ppc64le:send
 * #syscalls accept4|accept listen epoll_ctl epoll_wait|epoll_pwait epoll_pwait
 * #syscalls clock_gettime armv6l:clock_gettime64 armv7l:clock_gettime64
 */
int main(int argc, char **argv)
{
	int nfds, i, devnull_fd = -1, pidfile_fd = -1, quit_fd;
	struct epoll_event events[EPOLL_EVENTS];
	char *log_name, argv0[PATH_MAX], *name;
	struct ctx c = { 0 };
	struct rlimit limit;
	struct timespec now;
	struct sigaction sa;

	arch_avx2_exec(argv);

	isolate_initial();

	c.pasta_netns_fd = c.fd_tap = c.fd_tap_listen = -1;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = exit_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	if (argc < 1)
		exit(EXIT_FAILURE);

	strncpy(argv0, argv[0], PATH_MAX - 1);
	name = basename(argv0);
	if (strstr(name, "pasta")) {
		sa.sa_handler = pasta_child_handler;
		if (sigaction(SIGCHLD, &sa, NULL) || signal(SIGPIPE, SIG_IGN))
			die("Couldn't install signal handlers");

		c.mode = MODE_PASTA;
		log_name = "pasta";
	} else if (strstr(name, "passt")) {
		c.mode = MODE_PASST;
		log_name = "passt";
	} else {
		exit(EXIT_FAILURE);
	}

	madvise(pkt_buf, TAP_BUF_BYTES, MADV_HUGEPAGE);

	__openlog(log_name, 0, LOG_DAEMON);

	/* Meaning we don't know yet: log everything. LOG_EMERG is unused */
	__setlogmask(LOG_MASK(LOG_EMERG));

	c.epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (c.epollfd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	if (getrlimit(RLIMIT_NOFILE, &limit)) {
		perror("getrlimit");
		exit(EXIT_FAILURE);
	}
	c.nofile = limit.rlim_cur = limit.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &limit)) {
		perror("setrlimit");
		exit(EXIT_FAILURE);
	}
	sock_probe_mem(&c);

	conf(&c, argc, argv);
	trace_init(c.trace);

	if (c.force_stderr || isatty(fileno(stdout)))
		__openlog(log_name, LOG_PERROR, LOG_DAEMON);

	quit_fd = pasta_netns_quit_init(&c);

	tap_sock_init(&c);

	clock_gettime(CLOCK_MONOTONIC, &now);

	if ((!c.no_udp && udp_init(&c)) || (!c.no_tcp && tcp_init(&c)))
		exit(EXIT_FAILURE);

	if (!c.no_icmp)
		icmp_init();

	proto_update_l2_buf(c.mac_guest, c.mac, &c.ip4.addr);

	if (c.ifi4 && !c.no_dhcp)
		dhcp_init();

	if (c.ifi6 && !c.no_dhcpv6)
		dhcpv6_init(&c);

	pcap_init(&c);

	if (!c.foreground) {
		if ((devnull_fd = open("/dev/null", O_RDWR | O_CLOEXEC)) < 0) {
			perror("/dev/null open");
			exit(EXIT_FAILURE);
		}
	}

	if (*c.pid_file) {
		if ((pidfile_fd = open(c.pid_file,
				       O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
				       S_IRUSR | S_IWUSR)) < 0) {
			perror("PID file open");
			exit(EXIT_FAILURE);
		}
	}

	if (isolate_prefork(&c))
		die("Failed to sandbox process, exiting");

	/* Once the log mask is not LOG_EMERG, we will no longer
	 * log to stderr if there was a log file specified.
	 */
	if (c.debug)
		__setlogmask(LOG_UPTO(LOG_DEBUG));
	else if (c.quiet)
		__setlogmask(LOG_UPTO(LOG_ERR));
	else
		__setlogmask(LOG_UPTO(LOG_INFO));

	if (!c.foreground)
		__daemon(pidfile_fd, devnull_fd);
	else
		write_pidfile(pidfile_fd, getpid());

	if (c.keep_child_pid > 0) {
		kill(c.keep_child_pid, SIGUSR1);
	} else if (pasta_child_pid) {
		kill(pasta_child_pid, SIGUSR1);
	}

	isolate_postfork(&c);

	timer_init(&c, &now);

loop:
	/* NOLINTNEXTLINE(bugprone-branch-clone): intervals can be the same */
	/* cppcheck-suppress [duplicateValueTernary, unmatchedSuppression] */
	nfds = epoll_wait(c.epollfd, events, EPOLL_EVENTS, TIMER_INTERVAL);
	if (nfds == -1 && errno != EINTR) {
		perror("epoll_wait");
		exit(EXIT_FAILURE);
	}

	clock_gettime(CLOCK_MONOTONIC, &now);

	for (i = 0; i < nfds; i++) {
		union epoll_ref ref = *((union epoll_ref *)&events[i].data.u64);
		int fd = events[i].data.fd;

		if (fd == c.fd_tap || fd == c.fd_tap_listen)
			tap_handler(&c, fd, events[i].events, &now);
		else if (fd == quit_fd)
			pasta_netns_quit_handler(&c, fd);
		else
			sock_handler(&c, ref, events[i].events, &now);
	}

	post_handler(&c, &now);

	goto loop;
}

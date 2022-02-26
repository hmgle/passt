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

#include <sched.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <netinet/ip.h>
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
#include <sys/prctl.h>
#include <stddef.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/icmpv6.h>

#include "util.h"
#include "seccomp.h"
#include "passt.h"
#include "dhcp.h"
#include "dhcpv6.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "pcap.h"
#include "tap.h"
#include "conf.h"
#include "pasta.h"

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
static void sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
			 struct timespec *now)
{
	debug("%s: %s packet from socket %i (events: 0x%08x)",
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
static void post_handler(struct ctx *c, struct timespec *now)
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

	CALL_PROTO_HANDLER(c, now, tcp, TCP);
	CALL_PROTO_HANDLER(c, now, udp, UDP);
	CALL_PROTO_HANDLER(c, now, icmp, ICMP);

#undef CALL_PROTO_HANDLER
}

/**
 * timer_init() - Set initial timestamp for timer runs to current time
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void timer_init(struct ctx *c, struct timespec *now)
{
	c->tcp.timer_run = c->udp.timer_run = c->icmp.timer_run = *now;
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

/**
 * seccomp() - Set up seccomp filters depending on mode, won't return on failure
 * @c:		Execution context
 */
static void seccomp(struct ctx *c)
{
	struct sock_fprog prog;

	if (c->mode == MODE_PASST) {
		prog.len = (unsigned short)ARRAY_SIZE(filter_passt);
		prog.filter = filter_passt;
	} else {
		prog.len = (unsigned short)ARRAY_SIZE(filter_pasta);
		prog.filter = filter_pasta;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl");
		exit(EXIT_FAILURE);
	}
}

/**
 * check_root() - Warn if root in init, exit if we can't drop to nobody
 */
static void check_root(void)
{
	struct passwd *pw;
	char buf[BUFSIZ];
	int fd;

	if (getuid() && geteuid())
		return;

	if ((fd = open("/proc/self/uid_map", O_RDONLY)) < 0)
		return;

	if (read(fd, buf, BUFSIZ) > 0 &&
	    strcmp(buf, "         0          0 4294967295")) {
		close(fd);
		return;
	}

	close(fd);

	fprintf(stderr, "Don't run this as root. Changing to nobody...\n");
#ifndef GLIBC_NO_STATIC_NSS
	pw = getpwnam("nobody");
	if (!pw) {
		perror("getpwnam");
		exit(EXIT_FAILURE);
	}

	if (!initgroups(pw->pw_name, pw->pw_gid) &&
	    !setgid(pw->pw_gid) && !setuid(pw->pw_uid))
		return;
#else
	(void)pw;
#endif

	fprintf(stderr, "Can't change to user/group nobody, exiting");
	exit(EXIT_FAILURE);
}

/**
 * sandbox() - Unshare IPC, mount, PID, UTS, and user namespaces, "unmount" root
 *
 * Return: negative error code on failure, zero on success
 */
static int sandbox(struct ctx *c)
{
	int flags = CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS;

	errno = 0;

	if (!c->netns_only) {
		if (c->pasta_userns_fd == -1)
			flags |= CLONE_NEWUSER;
		else
			setns(c->pasta_userns_fd, CLONE_NEWUSER);
	}

	c->pasta_userns_fd = -1;

	/* If we run in foreground, we have no chance to actually move to a new
	 * PID namespace. For passt, use CLONE_NEWPID anyway, in case somebody
	 * ever gets around seccomp profiles -- there's no harm in passing it.
	 */
	if (!c->foreground || c->mode == MODE_PASST)
		flags |= CLONE_NEWPID;

	unshare(flags);

	mount("", "/", "", MS_UNBINDABLE | MS_REC, NULL);
	mount("", TMPDIR, "tmpfs", MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RDONLY,
	      "nr_inodes=2,nr_blocks=0");
	if (chdir(TMPDIR))
		return -errno;

	syscall(SYS_pivot_root, ".", ".");
	umount2(".", MNT_DETACH | UMOUNT_NOFOLLOW);

	if (errno)
		return -errno;

	drop_caps();	/* Relative to the new user namespace this time. */

	return 0;
}

/**
 * exit_handler() - Signal handler for SIGQUIT and SIGTERM
 * @unused:	Unused, handler deals with SIGQUIT and SIGTERM only
 *
 * TODO: After unsharing the PID namespace and forking, SIG_DFL for SIGTERM and
 * SIGQUIT unexpectedly doesn't cause the process to terminate, figure out why.
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
	struct ctx c = { 0 };
	struct rlimit limit;
	struct timespec now;
	struct sigaction sa;
	char *log_name;

	check_root();
	drop_caps();

	c.pasta_userns_fd = c.pasta_netns_fd = c.fd_tap = c.fd_tap_listen = -1;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = exit_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	if (argc < 1)
		exit(EXIT_FAILURE);

	if (strstr(argv[0], "pasta")) {
		sa.sa_handler = pasta_child_handler;
		sigaction(SIGCHLD, &sa, NULL);
		signal(SIGPIPE, SIG_IGN);

		c.mode = MODE_PASTA;
		log_name = "pasta";
	} else if (strstr(argv[0], "passt")) {
		c.mode = MODE_PASST;
		log_name = "passt";
	} else {
		exit(EXIT_FAILURE);
	}

	madvise(pkt_buf, TAP_BUF_BYTES, MADV_HUGEPAGE);

	__openlog(log_name, 0, LOG_DAEMON);

	__setlogmask(LOG_MASK(LOG_EMERG));

	conf(&c, argc, argv);

	if (!c.debug && (c.stderr || isatty(fileno(stdout))))
		__openlog(log_name, LOG_PERROR, LOG_DAEMON);

	c.epollfd = epoll_create1(0);
	if (c.epollfd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	quit_fd = pasta_netns_quit_init(&c);

	if (getrlimit(RLIMIT_NOFILE, &limit)) {
		perror("getrlimit");
		exit(EXIT_FAILURE);
	}
	limit.rlim_cur = limit.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &limit)) {
		perror("setrlimit");
		exit(EXIT_FAILURE);
	}
	sock_probe_mem(&c);

	c.fd_tap = c.fd_tap_listen = -1;
	tap_sock_init(&c);

	clock_gettime(CLOCK_MONOTONIC, &now);

	if ((!c.no_udp && udp_sock_init(&c, &now)) ||
	    (!c.no_tcp && tcp_sock_init(&c, &now)))
		exit(EXIT_FAILURE);

	proto_update_l2_buf(c.mac_guest, c.mac, &c.addr4);

	if (c.v4 && !c.no_dhcp)
		dhcp_init();

	if (c.v6 && !c.no_dhcpv6)
		dhcpv6_init(&c);

	if (c.debug)
		__setlogmask(LOG_UPTO(LOG_DEBUG));
	else if (c.quiet)
		__setlogmask(LOG_UPTO(LOG_ERR));
	else
		__setlogmask(LOG_UPTO(LOG_INFO));

	pcap_init(&c);

	if (!c.foreground)
		devnull_fd = open("/dev/null", O_RDWR);

	if (*c.pid_file)
		pidfile_fd = open(c.pid_file,
				  O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

	if (sandbox(&c)) {
		err("Failed to sandbox process, exiting\n");
		exit(EXIT_FAILURE);
	}

	if (!c.foreground)
		__daemon(pidfile_fd, devnull_fd);
	else
		write_pidfile(pidfile_fd, getpid());

	prctl(PR_SET_DUMPABLE, 0);

	seccomp(&c);

	timer_init(&c, &now);

loop:
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

// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * pasta.c - pasta (namespace) specific implementations
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * #syscalls:pasta clone waitid exit exit_group rt_sigprocmask
 * #syscalls:pasta rt_sigreturn|sigreturn armv6l:sigreturn armv7l:sigreturn
 * #syscalls:pasta ppc64:sigreturn s390x:sigreturn
 */

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/syscall.h>

#include "util.h"
#include "passt.h"
#include "isolation.h"
#include "netlink.h"
#include "log.h"

/* PID of child, in case we created a namespace */
static int pasta_child_pid;

/**
 * pasta_child_handler() - Exit once shell exits (if we started it), reap clones
 * @signal:	Unused, handler deals with SIGCHLD only
 */
void pasta_child_handler(int signal)
{
	siginfo_t infop;

	(void)signal;

	if (signal != SIGCHLD)
		return;

	if (pasta_child_pid &&
	    !waitid(P_PID, pasta_child_pid, &infop, WEXITED | WNOHANG)) {
		if (infop.si_pid == pasta_child_pid)
			exit(EXIT_SUCCESS);
			/* Nothing to do, detached PID namespace going away */
	}

	waitid(P_ALL, 0, NULL, WEXITED | WNOHANG);
	waitid(P_ALL, 0, NULL, WEXITED | WNOHANG);
}

/**
 * pasta_wait_for_ns() - Busy loop until we can enter the target namespace
 * @arg:	Execution context
 *
 * Return: 0
 */
static int pasta_wait_for_ns(void *arg)
{
	struct ctx *c = (struct ctx *)arg;
	int flags = O_RDONLY | O_CLOEXEC;
	char ns[PATH_MAX];

	snprintf(ns, PATH_MAX, "/proc/%i/ns/net", pasta_child_pid);
	do
		while ((c->pasta_netns_fd = open(ns, flags)) < 0);
	while (setns(c->pasta_netns_fd, CLONE_NEWNET) &&
	       !close(c->pasta_netns_fd));

	return 0;
}

/**
 * ns_check() - Check if we can enter configured namespaces
 * @arg:	Execution context
 *
 * Return: 0
 */
static int ns_check(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	if (setns(c->pasta_netns_fd, CLONE_NEWNET))
		c->pasta_netns_fd = -1;

	return 0;

}

/**
 * pasta_open_ns() - Open network namespace descriptors
 * @c:		Execution context
 * @netns:	network namespace path
 *
 * Return: 0 on success, negative error code otherwise
 */
void pasta_open_ns(struct ctx *c, const char *netns)
{
	int nfd = -1;

	nfd = open(netns, O_RDONLY | O_CLOEXEC);
	if (nfd < 0) {
		err("Couldn't open network namespace %s", netns);
		exit(EXIT_FAILURE);
	}

	c->pasta_netns_fd = nfd;

	NS_CALL(ns_check, c);

	if (c->pasta_netns_fd < 0) {
		err("Couldn't switch to pasta namespaces");
		exit(EXIT_FAILURE);
	}

	if (!c->no_netns_quit) {
		char buf[PATH_MAX] = { 0 };

		strncpy(buf, netns, PATH_MAX - 1);
		strncpy(c->netns_base, basename(buf), PATH_MAX - 1);
		strncpy(buf, netns, PATH_MAX - 1);
		strncpy(c->netns_dir, dirname(buf), PATH_MAX - 1);
	}
}

/**
 * struct pasta_setup_ns_arg - Argument for pasta_setup_ns()
 * @exe:	Executable to run
 * @argv:	Command and arguments to run
 */
struct pasta_setup_ns_arg {
	const char *exe;
	char *const *argv;
};

/**
 * pasta_setup_ns() - Map credentials, enable access to ping sockets, run shell
 * @arg:	See @pasta_setup_ns_arg
 *
 * Return: this function never returns
 */
static int pasta_setup_ns(void *arg)
{
	const struct pasta_setup_ns_arg *a;

	FWRITE("/proc/sys/net/ipv4/ping_group_range", "0 0",
	       "Cannot set ping_group_range, ICMP requests might fail");

	a = (const struct pasta_setup_ns_arg *)arg;
	execvp(a->exe, a->argv);

	perror("execvp");
	exit(EXIT_FAILURE);
}

/**
 * pasta_start_ns() - Fork command in new namespace if target ns is not given
 * @c:		Execution context
 * @argc:	Number of arguments for spawned command
 * @argv:	Command to spawn and arguments
 */
void pasta_start_ns(struct ctx *c, int argc, char *argv[])
{
	struct pasta_setup_ns_arg arg = {
		.exe = argv[0],
		.argv = argv,
	};
	char ns_fn_stack[NS_FN_STACK_SIZE];
	char *sh_argv[] = { NULL, NULL };
	char sh_arg0[PATH_MAX + 1];

	c->foreground = 1;
	if (!c->debug)
		c->quiet = 1;


	if (argc == 0) {
		arg.exe = getenv("SHELL");
		if (!arg.exe)
			arg.exe = "/bin/sh";

		if ((size_t)snprintf(sh_arg0, sizeof(sh_arg0),
				     "-%s", arg.exe) >= sizeof(sh_arg0)) {
			err("$SHELL is too long (%u bytes)",
			    strlen(arg.exe));
			exit(EXIT_FAILURE);
		}
		sh_argv[0] = sh_arg0;
		arg.argv = sh_argv;
	}

	pasta_child_pid = clone(pasta_setup_ns,
				ns_fn_stack + sizeof(ns_fn_stack) / 2,
				CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET |
				CLONE_NEWUTS,
				(void *)&arg);

	if (pasta_child_pid == -1) {
		perror("clone");
		exit(EXIT_FAILURE);
	}

	drop_caps();

	NS_CALL(pasta_wait_for_ns, c);
}

/**
 * pasta_ns_conf() - Set up loopback and tap interfaces in namespace as needed
 * @c:		Execution context
 */
void pasta_ns_conf(struct ctx *c)
{
	nl_link(1, 1 /* lo */, MAC_ZERO, 1, 0);

	if (c->pasta_conf_ns) {
		int prefix_len;

		nl_link(1, c->pasta_ifi, c->mac_guest, 1, c->mtu);

		if (c->ifi4) {
			prefix_len = __builtin_popcount(c->ip4.mask);
			nl_addr(1, c->pasta_ifi, AF_INET, &c->ip4.addr,
				&prefix_len, NULL);
			nl_route(1, c->pasta_ifi, AF_INET, &c->ip4.gw);
		}

		if (c->ifi6) {
			prefix_len = 64;
			nl_addr(1, c->pasta_ifi, AF_INET6, &c->ip6.addr,
				&prefix_len, NULL);
			nl_route(1, c->pasta_ifi, AF_INET6, &c->ip6.gw);
		}
	} else {
		nl_link(1, c->pasta_ifi, c->mac_guest, 0, 0);
	}

	proto_update_l2_buf(c->mac_guest, NULL, NULL);
}

/**
 * pasta_netns_quit_init() - Watch network namespace to quit once it's gone
 * @c:		Execution context
 *
 * Return: inotify file descriptor, -1 on failure or if not needed/applicable
 */
int pasta_netns_quit_init(struct ctx *c)
{
	int flags = O_NONBLOCK | O_CLOEXEC;
	struct epoll_event ev = { .events = EPOLLIN };
	int inotify_fd;

	if (c->mode != MODE_PASTA || c->no_netns_quit || !*c->netns_base)
		return -1;

	if ((inotify_fd = inotify_init1(flags)) < 0) {
		perror("inotify_init(): won't quit once netns is gone");
		return -1;
	}

	if (inotify_add_watch(inotify_fd, c->netns_dir, IN_DELETE) < 0) {
		perror("inotify_add_watch(): won't quit once netns is gone");
		return -1;
	}

	ev.data.fd = inotify_fd;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, inotify_fd, &ev);

	return inotify_fd;
}

/**
 * pasta_netns_quit_handler() - Handle ns directory events, exit if ns is gone
 * @c:		Execution context
 * @inotify_fd:	inotify file descriptor with watch on namespace directory
 */
void pasta_netns_quit_handler(struct ctx *c, int inotify_fd)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	struct inotify_event *in_ev = (struct inotify_event *)buf;

	if (read(inotify_fd, buf, sizeof(buf)) < (ssize_t)sizeof(*in_ev))
		return;

	if (strncmp(in_ev->name, c->netns_base, sizeof(c->netns_base)))
		return;

	info("Namespace %s is gone, exiting", c->netns_base);
	exit(EXIT_SUCCESS);
}

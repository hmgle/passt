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
 * #syscalls:pasta clone unshare waitid kill execve exit_group rt_sigprocmask
 * #syscalls:pasta geteuid getdents64 readlink setsid nanosleep clock_nanosleep
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
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
#include "netlink.h"

/* PID of child, in case we created a namespace, and its procfs link */
static int pasta_child_pid;
static char pasta_child_ns[PATH_MAX];

/**
 * pasta_ns_cleanup() - Look for processes in namespace, terminate them
 */
static void pasta_ns_cleanup(void)
{
	char proc_path[PATH_MAX], ns_link[PATH_MAX], buf[BUFSIZ];
	int recheck = 0, found = 0, waited = 0;
	int dir_fd, n;

	if (!*pasta_child_ns)
		return;

loop:
	if ((dir_fd = open("/proc", O_RDONLY | O_DIRECTORY)) < 0)
		return;

	while ((n = syscall(SYS_getdents64, dir_fd, buf, BUFSIZ)) > 0) {
		struct dirent *dp = (struct dirent *)buf;
		int pos = 0;

		while (pos < n) {
			pid_t pid;

			errno = 0;
			pid = strtol(dp->d_name, NULL, 0);
			if (!pid || errno)
				goto next;

			snprintf(proc_path, PATH_MAX, "/proc/%i/ns/net", pid);
			if (readlink(proc_path, ns_link, PATH_MAX) < 0)
				goto next;

			if (!strncmp(ns_link, pasta_child_ns, PATH_MAX)) {
				found = 1;
				if (waited)
					kill(pid, SIGKILL);
				else
					kill(pid, SIGQUIT);
			}
next:
			dp = (struct dirent *)(buf + (pos += dp->d_reclen));
		}
	}

	close(dir_fd);

	if (!found)
		return;

	if (waited) {
		if (recheck) {
			info("Some processes in namespace didn't quit");
		} else {
			found = 0;
			recheck = 1;
			goto loop;
		}
		return;
	}

	info("Waiting for all processes in namespace to terminate");
	sleep(1);
	waited = 1;
	goto loop;
}

/**
 * pasta_child_handler() - Exit once shell exits (if we started it), reap clones
 * @signal:	Unused, handler deals with SIGCHLD only
 */
void pasta_child_handler(int signal)
{
	siginfo_t infop;

	(void)signal;

	if (pasta_child_pid &&
	    !waitid(P_PID, pasta_child_pid, &infop, WEXITED | WNOHANG)) {
		if (infop.si_pid == pasta_child_pid) {
			pasta_ns_cleanup();
			exit(EXIT_SUCCESS);
		}
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
	char ns[PATH_MAX];

	if (c->netns_only)
		goto netns;

	snprintf(ns, PATH_MAX, "/proc/%i/ns/user", pasta_child_pid);
	do
		while ((c->pasta_userns_fd = open(ns, O_RDONLY)) < 0);
	while (setns(c->pasta_userns_fd, 0) && !close(c->pasta_userns_fd));

netns:
	snprintf(ns, PATH_MAX, "/proc/%i/ns/net", pasta_child_pid);
	do
		while ((c->pasta_netns_fd = open(ns, O_RDONLY)) < 0);
	while (setns(c->pasta_netns_fd, 0) && !close(c->pasta_netns_fd));

	return 0;
}

/**
 * pasta_start_ns() - Fork shell in new namespace if target ns is not given
 * @c:		Execution context
 */
void pasta_start_ns(struct ctx *c)
{
	char buf[BUFSIZ], *shell, proc_path[PATH_MAX];
	int euid = geteuid();
	int fd;

	c->foreground = 1;
	if (!c->debug)
		c->quiet = 1;

	if ((pasta_child_pid = fork()) == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if (pasta_child_pid) {
		NS_CALL(pasta_wait_for_ns, c);

		snprintf(proc_path, PATH_MAX, "/proc/%i/ns/net",
			 pasta_child_pid);
		readlink(proc_path, pasta_child_ns, PATH_MAX);

		return;
	}

	if (unshare(CLONE_NEWNET | (c->netns_only ? 0 : CLONE_NEWUSER))) {
		perror("unshare");
		exit(EXIT_FAILURE);
	}

	if (!c->netns_only) {
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
	}

	fd = open("/proc/sys/net/ipv4/ping_group_range", O_WRONLY);
	write(fd, "0 0", strlen("0 0"));
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
 * pasta_ns_conf() - Set up loopback and tap interfaces in namespace as needed
 * @c:		Execution context
 */
void pasta_ns_conf(struct ctx *c)
{
	nl_link(1, 1 /* lo */, MAC_ZERO, 1, 0);

	if (c->pasta_conf_ns) {
		int prefix_len;

		nl_link(1, c->pasta_ifi, c->mac_guest, 1, c->mtu);

		if (c->v4) {
			prefix_len = __builtin_popcount(c->mask4);
			nl_addr(1, c->pasta_ifi, AF_INET, &c->addr4,
				&prefix_len, NULL);
			nl_route(1, c->pasta_ifi, AF_INET, &c->gw4);
		}

		if (c->v6) {
			prefix_len = 64;
			nl_addr(1, c->pasta_ifi, AF_INET6, &c->addr6,
				&prefix_len, NULL);
			nl_route(1, c->pasta_ifi, AF_INET6, &c->gw6);
		}
	} else {
		nl_link(1, c->pasta_ifi, c->mac_guest, 0, 0);
	}

	proto_update_l2_buf(c->mac_guest, NULL, NULL);
}

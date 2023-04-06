// SPDX-License-Identifier: GPL-2.0-or-later

/* nstool - maintain a namespace to be entered by other processes
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <sched.h>

#define	ARRAY_SIZE(a)	((int)(sizeof(a) / sizeof((a)[0])))

#define die(...)				\
	do {					\
		fprintf(stderr, __VA_ARGS__);	\
		exit(1);			\
	} while (0)

struct ns_type {
	int flag;
	const char *name;
};

const struct ns_type nstypes[] = {
	{ CLONE_NEWCGROUP, "cgroup" },
	{ CLONE_NEWIPC, "ipc" },
	{ CLONE_NEWNET, "net" },
	{ CLONE_NEWNS, "mnt" },
	{ CLONE_NEWPID, "pid" },
	{ CLONE_NEWTIME, "time" },
	{ CLONE_NEWUSER, "user" },
	{ CLONE_NEWUTS, "uts" },
};

struct holder_info {
	pid_t pid;
	uid_t uid;
	gid_t gid;
};

static void usage(void)
{
	die("Usage:\n"
	    "  nstool hold SOCK\n"
	    "    Run within a set of namespaces, open a Unix domain socket\n"
	    "    (the \"control socket\") at SOCK and wait for requests from\n"
	    "    other nstool subcommands.\n"
	    "  nstool info [-pw] pid SOCK\n"
	    "    Print information about the nstool hold process with control\n"
	    "    socket at SOCK\n"
	    "      -p    Print just the holder's PID as seen by the caller\n"
	    "      -w    Retry connecting to SOCK until it is ready\n"
	    "  nstool stop SOCK\n"
	    "    Instruct the nstool hold with control socket at SOCK to\n"
	    "    terminate.\n");
}

static int connect_ctl(const char *sockpath, bool wait,
		       struct holder_info *info,
		       struct ucred *peercred)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	struct holder_info discard;
	ssize_t len;
	int rc;

	if (fd < 0)
		die("socket(): %s\n", strerror(errno));

	strncpy(addr.sun_path, sockpath, UNIX_PATH_MAX);

	do {
		rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
		if (rc < 0 &&
		    (!wait || (errno != ENOENT && errno != ECONNREFUSED)))
			die("connect() to %s: %s\n", sockpath, strerror(errno));
	} while (rc < 0);

	if (!info)
		info = &discard;

	/* Always read the info structure, even if we don't need it,
	 * so that the holder doesn't get a broken pipe error
	 */
	len = read(fd, info, sizeof(*info));
	if (len < 0)
		die("read() on control socket %s: %s\n", sockpath, strerror(errno));
	if ((size_t)len < sizeof(*info))
		die("short read() on control socket %s\n", sockpath);

	if (peercred) {
		socklen_t optlen = sizeof(*peercred);

		rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
				peercred, &optlen);
		if (rc < 0)
			die("getsockopet(SO_PEERCRED) %s: %s\n",
			    sockpath, strerror(errno));
	}

	return fd;
}

static void cmd_hold(int argc, char *argv[])
{
	int fd = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	const char *sockpath = argv[1];
	struct holder_info info;
	int rc;

	if (argc != 2)
		usage();

	if (fd < 0)
		die("socket(): %s\n", strerror(errno));

	strncpy(addr.sun_path, sockpath, UNIX_PATH_MAX);

	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0)
		die("bind() to %s: %s\n", sockpath, strerror(errno));

	rc = listen(fd, 0);
	if (rc < 0)
		die("listen() on %s: %s\n", sockpath, strerror(errno));

	info.pid = getpid();
	info.uid = getuid();
	info.gid = getgid();

	do {
		int afd = accept(fd, NULL, NULL);
		char buf;

		if (afd < 0)
			die("accept(): %s\n", strerror(errno));

		rc = write(afd, &info, sizeof(info));
		if (rc < 0)
			die("write(): %s\n", strerror(errno));
		if ((size_t)rc < sizeof(info))
			die("short write() on control socket\n");

		rc = read(afd, &buf, sizeof(buf));
		if (rc < 0)
			die("read(): %s\n", strerror(errno));
	} while (rc == 0);

	unlink(sockpath);
}

static ssize_t getlink(char *buf, size_t bufsiz, const char *fmt, ...)
{
	char linkpath[PATH_MAX];
	ssize_t linklen;
	va_list ap;

	va_start(ap, fmt);
	if (vsnprintf(linkpath, sizeof(linkpath), fmt, ap) >= PATH_MAX)
		die("Truncated path \"%s\"\n", linkpath);
	va_end(ap);

	linklen = readlink(linkpath, buf, bufsiz);
	if (linklen < 0)
		die("readlink() on %s: %s\n", linkpath, strerror(errno));
	if ((size_t)linklen >= bufsiz)
		die("Target of symbolic link %s is too long\n", linkpath);

	return linklen;
}

static int detect_namespaces(pid_t pid)
{
	int i;
	int flags = 0;

	for (i = 0; i < ARRAY_SIZE(nstypes); i++) {
		const struct ns_type *nst = &nstypes[i];
		char selflink[PATH_MAX], pidlink[PATH_MAX];
		ssize_t selflen, pidlen;

		selflen = getlink(selflink, sizeof(selflink),
				  "/proc/self/ns/%s", nst->name);
		pidlen = getlink(pidlink, sizeof(pidlink),
				 "/proc/%d/ns/%s", pid, nst->name);

		if ((selflen != pidlen) || memcmp(selflink, pidlink, selflen))
			flags |= nst->flag;
	}

	return flags;
}

static void print_nstypes(int flags)
{
	bool first = true;
	int i;

	for (i = 0; i < ARRAY_SIZE(nstypes); i++) {
		const struct ns_type *nst = &nstypes[i];

		if (!(flags & nst->flag))
			continue;

		printf("%s%s", first ? "" : ", " , nst->name);
		first = false;
		flags &= ~nst->flag;
	}

	if (flags)
		printf("%s0x%x", first ? "" : ", ", flags);
}

static void cmd_info(int argc, char *argv[])
{
	const struct option options[] = {
		{"pid",		no_argument, 	NULL,	'p' },
		{"wait",	no_argument,	NULL,	'w' },
		{ 0 },
	};
	bool pidonly = false, waitforsock = false;
	const char *optstring = "pw";
	struct holder_info info;
	struct ucred peercred;
	const char *sockpath;
	int fd, opt;

	do {
		opt = getopt_long(argc, argv, optstring, options, NULL);

		switch (opt) {
		case 'p':
			pidonly = true;
			break;
		case 'w':
			waitforsock = true;
			break;
		case -1:
			break;
		default:
			usage();
		}
	} while (opt != -1);

	if (optind != argc - 1) {
		fprintf(stderr, "B\n");
		usage();
	}

	sockpath = argv[optind];

	fd = connect_ctl(sockpath, waitforsock, &info, &peercred);

	close(fd);

	if (pidonly) {
		printf("%d\n", peercred.pid);
	} else {
		int flags = detect_namespaces(peercred.pid);

		printf("Namespaces: ");
		print_nstypes(flags);
		printf("\n");

		printf("As seen from calling context:\n");
		printf("\tPID:\t%d\n", peercred.pid);
		printf("\tUID:\t%u\n", peercred.uid);
		printf("\tGID:\t%u\n", peercred.gid);

		printf("As seen from holding context:\n");
		printf("\tPID:\t%d\n", info.pid);
		printf("\tUID:\t%u\n", info.uid);
		printf("\tGID:\t%u\n", info.gid);
	}
}

static void cmd_stop(int argc, char *argv[])
{
	const char *sockpath = argv[1];
	int fd, rc;
	char buf = 'Q';

	if (argc != 2)
		usage();

	fd = connect_ctl(sockpath, false, NULL, NULL);

	rc = write(fd, &buf, sizeof(buf));
	if (rc < 0)
		die("write() to %s: %s\n", sockpath, strerror(errno));

	close(fd);
}

int main(int argc, char *argv[])
{
	const char *subcmd = argv[1];
	int fd;

	if (argc < 2)
		usage();

	fd = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	if (fd < 0)
		die("socket(): %s\n", strerror(errno));

	if (strcmp(subcmd, "hold") == 0)
		cmd_hold(argc - 1, argv + 1);
	else if (strcmp(subcmd, "info") == 0)
		cmd_info(argc - 1, argv + 1);
	else if (strcmp(subcmd, "stop") == 0)
		cmd_stop(argc - 1, argv + 1);
	else
		usage();

	exit(0);
}

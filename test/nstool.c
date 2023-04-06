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
#include <sys/socket.h>
#include <linux/un.h>

#define die(...)				\
	do {					\
		fprintf(stderr, __VA_ARGS__);	\
		exit(1);			\
	} while (0)

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

static int connect_ctl(const char * sockpath, bool wait)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
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

	return fd;
}

static void cmd_hold(int argc, char *argv[])
{
	int fd = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	const char *sockpath = argv[1];
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

	printf("nstool hold: local PID=%d  local UID=%u  local GID=%u\n",
	       getpid(), getuid(), getgid());
	do {
		int afd = accept(fd, NULL, NULL);
		char buf;

		if (afd < 0)
			die("accept(): %s\n", strerror(errno));

		rc = read(afd, &buf, sizeof(buf));
		if (rc < 0)
			die("read(): %s\n", strerror(errno));
	} while (rc == 0);

	unlink(sockpath);
}

static void cmd_info(int argc, char *argv[])
{
	const struct option options[] = {
		{"pid",		no_argument, 	NULL,	'p' },
		{"wait",	no_argument,	NULL,	'w' },
		{ 0 },
	};
	bool pidonly = false, waitforsock = false;
	struct ucred peercred;
	socklen_t optlen = sizeof(peercred);
	const char *optstring = "pw";
	const char *sockpath;
	int fd, rc, opt;

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

	fd = connect_ctl(sockpath, waitforsock);

	rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
			&peercred, &optlen);
	if (rc < 0)
		die("getsockopet(SO_PEERCRED) %s: %s\n",
		    sockpath, strerror(errno));

	close(fd);

	if (pidonly) {
		printf("%d\n", peercred.pid);
	} else {
		printf("As seen from calling context:\n");
		printf("\tPID:\t%d\n", peercred.pid);
		printf("\tUID:\t%u\n", peercred.uid);
		printf("\tGID:\t%u\n", peercred.gid);
	}
}

static void cmd_stop(int argc, char *argv[])
{
	const char *sockpath = argv[1];
	int fd, rc;
	char buf = 'Q';

	if (argc != 2)
		usage();

	fd = connect_ctl(sockpath, false);

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

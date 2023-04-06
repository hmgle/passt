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
#include <errno.h>
#include <unistd.h>
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
	    "  nstool pid SOCK\n"
	    "    Print the pid of the nstool hold process with control socket\n"
	    "    at SOCK, as seen in the caller's namespace.\n"
	    "  nstool stop SOCK\n"
	    "    Instruct the nstool hold with control socket at SOCK to\n"
	    "    terminate.\n");
}

static void hold(int fd, const struct sockaddr_un *addr)
{
	int rc;

	rc = bind(fd, (struct sockaddr *)addr, sizeof(*addr));
	if (rc < 0)
		die("bind(): %s\n", strerror(errno));

	rc = listen(fd, 0);
	if (rc < 0)
		die("listen(): %s\n", strerror(errno));

	printf("nstool: local PID=%d  local UID=%u  local GID=%u\n",
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

	unlink(addr->sun_path);
}

static void pid(int fd, const struct sockaddr_un *addr)
{
	int rc;
	struct ucred peercred;
	socklen_t optlen = sizeof(peercred);

	do {
		rc = connect(fd, (struct sockaddr *)addr, sizeof(*addr));
		if (rc < 0 && errno != ENOENT && errno != ECONNREFUSED)
			die("connect(): %s\n", strerror(errno));
	} while (rc < 0);

	rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
			&peercred, &optlen);
	if (rc < 0)
		die("getsockopet(SO_PEERCRED): %s\n", strerror(errno));

	close(fd);

	printf("%d\n", peercred.pid);
}

static void stop(int fd, const struct sockaddr_un *addr)
{
	int rc;
	char buf = 'Q';

	rc = connect(fd, (struct sockaddr *)addr, sizeof(*addr));
	if (rc < 0)
		die("connect(): %s\n", strerror(errno));

	rc = write(fd, &buf, sizeof(buf));
	if (rc < 0)
		die("write(): %s\n", strerror(errno));

	close(fd);
}

int main(int argc, char *argv[])
{
	int fd;
	const char *sockname;
	struct sockaddr_un sockaddr = {
		.sun_family = AF_UNIX,
	};

	if (argc != 3)
		usage();

	sockname = argv[2];
	strncpy(sockaddr.sun_path, sockname, UNIX_PATH_MAX);

	fd = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	if (fd < 0)
		die("socket(): %s\n", strerror(errno));

	if (strcmp(argv[1], "hold") == 0)
		hold(fd, &sockaddr);
	else if (strcmp(argv[1], "pid") == 0)
		pid(fd, &sockaddr);
	else if (strcmp(argv[1], "stop") == 0)
		stop(fd, &sockaddr);
	else
		usage();

	exit(0);
}

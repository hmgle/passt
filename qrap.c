// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *
 * qrap.c - qemu wrapper connecting UNIX domain socket to socket file descriptor
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * TODO: Implement this functionality directly in qemu: we have TCP and UDP
 * socket back-ends already.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/limits.h>
#include <limits.h>
#include <net/if.h>

#include "passt.h"

static char *qemu_names[] = {
	"kvm",
	"qemu-kvm",
#ifdef ARCH
	"qemu-system-" ARCH,
#endif
	"/usr/libexec/qemu-kvm",
	NULL,
};

#define DEFAULT_FD	5

/**
 * usage() - Print usage and exit
 * @name:	Executable name
 */
void usage(const char *name)
{
	fprintf(stderr, "Usage: %s [FDNUM QEMU_CMD] ...\n", name);
	fprintf(stderr, "\n");
	fprintf(stderr, "If first and second arguments aren't a socket number\n"
			"and a path, %s will try to locate a qemu binary\n"
			"and directly patch the command line\n", name);

	exit(EXIT_FAILURE);
}

/**
 * main() - Entry point and main loop
 * @argc:	Argument count
 * @argv:	File descriptor number, then qemu with arguments
 *
 * Return: 0 once interrupted, non-zero on failure
 */
int main(int argc, char **argv)
{
	char *qemu_argv[ARG_MAX], net_id[ARG_MAX] = { 0 }, *net_id_end;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = UNIX_SOCK_PATH,
	};
	int i, s, qemu_argc = 0;
	char fd_str[ARG_MAX];
	long fd;

	if (argc >= 3) {
		fd = strtol(argv[1], NULL, 0);
		if (fd >= 3 && fd < INT_MAX && !errno) {
			char env_path[ARG_MAX], *p, command[ARG_MAX];

			strncpy(env_path, getenv("PATH"), ARG_MAX);
			p = strtok(env_path, ":");
			while (p) {
				snprintf(command, ARG_MAX, "%s/%s", p, argv[2]);
				if (!access(command, X_OK))
					goto valid_args;

				p = strtok(NULL, ":");
			}
		}
	}

	fd = DEFAULT_FD;
	for (qemu_argc = 1, i = 1; i < argc; i++) {
		char *p;

		if (!strcmp(argv[i], "-net") || (!strcmp(argv[i], "-netdev"))) {
			i++;
			continue;
		}

		if (!*net_id && (p = strstr(argv[i], ",netdev=")))
			strncpy(net_id, p + strlen(",netdev="), ARG_MAX);

		qemu_argv[qemu_argc++] = argv[i];
	}

	if (*net_id) {
		net_id_end = strpbrk(net_id, ", ");
		if (net_id_end)
			*net_id_end = 0;
	}

	qemu_argv[qemu_argc++] = "-netdev";
	snprintf(fd_str, ARG_MAX, "socket,fd=%u,id=%s", DEFAULT_FD,
		 *net_id ? net_id : "hostnet0");
	qemu_argv[qemu_argc++] = fd_str;
	qemu_argv[qemu_argc] = NULL;

valid_args:
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (connect(s, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if (dup2(s, (int)fd) < 0) {
		perror("dup");
		exit(EXIT_FAILURE);
	}

	close(s);

	if (qemu_argc) {
		char **name;

		for (name = qemu_names; *name; name++) {
			qemu_argv[0] = *name;
			execvp(*name, qemu_argv);
			if (errno != ENOENT) {
				perror("execvp");
				usage(argv[0]);
			}
		}
		if (errno == ENOENT)
			fprintf(stderr, "Couldn't find qemu command\n");
	} else {
		execvp(argv[2], argv + 2);
	}

	perror("execvp");

	return EXIT_FAILURE;
}

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

#define STRINGIFY(x)	#x
#define STR(x)		STRINGIFY(x)

static char *qemu_names[] = {
	"kvm",
	"qemu-kvm",
#ifdef ARCH
	"qemu-system-" ARCH,
#endif
	"/usr/libexec/qemu-kvm",
	NULL,
};

static const struct drop_arg {
	char *name;
	char *val;
} drop_args[] = {
	{ "-netdev",	NULL },
	{ "-net",	NULL },
	{ "-device",	"virtio-net-pci," },
	{ "-device",	"virtio-net-ccw," },
	{ "-device",	"e1000," },
	{ "-device",	"rtl8139," },
	{ 0 },
};

static const struct pci_dev {
	char *mach;
	char *name;
	char *template;
	char *template_post;
	int first;
	int last;
} pci_devs[] = {
	{ "pc-q35",	"virtio-net-pci",
		"bus=pci.", ",addr=0x0",	1,			16 },
	{ "pc-",	"virtio-net-pci",
		"bus=pci.0,addr=0x", "",	2, /* 1: ISA bridge */	16 },
	{ "s390-ccw",	"virtio-net-ccw",
		"devno=fe.0.", "",		1,			16 },
	{ 0 },
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
	char *qemu_argv[ARG_MAX], dev_str[ARG_MAX];
	int i, s, qemu_argc = 0, addr_map = 0, has_dev = 0;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = UNIX_SOCK_PATH,
	};
	const struct pci_dev *dev = NULL;
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

	for (i = 1; i < argc - 1; i++) {
		if (strcmp(argv[i], "-machine"))
			continue;

		for (dev = pci_devs; dev->mach; dev++) {
			if (strstr(argv[i + 1], dev->mach) == argv[i + 1])
				break;
		}
	}

	if (!dev || !dev->mach)
		dev = pci_devs;

	for (qemu_argc = 1, i = 1; i < argc; i++) {
		const struct drop_arg *a;

		for (a = drop_args; a->name; a++) {
			if (!strcmp(argv[i], a->name)) {
				if (!a->val)
					break;

				if (i + 1 < argc &&
				    strstr(argv[i + 1], a->val) == argv[i + 1])
					break;
			}
		}
		if (a->name) {
			i++;
			continue;
		}

		if (!strcmp(argv[i], "-device") && i + 1 < argc) {
			char *p;
			long n;

			has_dev = 1;

			if ((p = strstr(argv[i + 1], dev->template))) {
				n = strtol(p + strlen(dev->template), NULL, 16);
				if (!errno)
					addr_map |= (1 << n);
			}
		}

		qemu_argv[qemu_argc++] = argv[i];
	}

	for (i = dev->first; i < dev->last; i++) {
		if (!(addr_map & (1 << i)))
			break;
	}
	if (i == dev->last) {
		fprintf(stderr, "Couldn't find free address for device\n");
		usage(argv[0]);
	}

	if (has_dev) {
		qemu_argv[qemu_argc++] = "-device";
		snprintf(dev_str, ARG_MAX, "%s,%s%x%s,netdev=hostnet0",
			 dev->name, dev->template, i, dev->template_post);
		qemu_argv[qemu_argc++] = dev_str;
	}

	qemu_argv[qemu_argc++] = "-netdev";
	qemu_argv[qemu_argc++] = "socket,fd=" STR(DEFAULT_FD) ",id=hostnet0";
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

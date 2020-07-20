/* PASST - Plug A Simple Socket Transport
 *
 * qrap.c - qemu wrapper connecting UNIX domain socket to tap file descriptor
 *
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * License: GPLv2
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
#include <limits.h>
#include <linux/if_ether.h>
#include <net/if.h>

#include "passt.h"

/**
 * usage() - Print usage and exit
 * @name:	Executable name
 */
void usage(const char *name)
{
	fprintf(stderr, "Usage: %s FDNUM QEMU_CMD ...\n", name);

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
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = UNIX_SOCK_PATH,
	};
	long fd;
	int s;

	if (argc < 3)
		usage(argv[0]);

	fd = strtol(argv[1], NULL, 0);
	if (fd < 3 || fd > INT_MAX || errno)
		usage(argv[0]);

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

	execvp(argv[2], argv + 2);
	perror("execvp");

	return EXIT_FAILURE;
}

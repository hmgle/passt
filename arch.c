// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * arch.c - Architecture-specific implementations
 *
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * arch_avx2_exec() - Run AVX2 build if supported, drop suffix from argv[0]
 * @argv:	Arguments from command line
 */
#ifdef __x86_64__
static char avx2_path[PATH_MAX];

void arch_avx2_exec(char **argv)
{
	char *p = strstr(argv[0], ".avx2");

	if (p) {
		*p = 0;
	} else if (__builtin_cpu_supports("avx2")) {
		snprintf(avx2_path, PATH_MAX, "%s.avx2", argv[0]);
		argv[0] = avx2_path;
		execve(avx2_path, argv, environ);
		perror("Can't run AVX2 build, using non-AVX2 version");
	}
}
#else
void arch_avx2_exec(char **argv) { (void)argv; }
#endif

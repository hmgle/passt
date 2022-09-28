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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * arch_avx2_exec() - Switch to AVX2 build if supported
 * @argv:	Arguments from command line
 */
#ifdef __x86_64__
void arch_avx2_exec(char **argv)
{
	char exe[PATH_MAX] = { 0 }, *p;

	if (readlink("/proc/self/exe", exe, PATH_MAX - 1) < 0) {
		perror("readlink /proc/self/exe");
		exit(EXIT_FAILURE);
	}

	p = strstr(exe, ".avx2");
	if (p && strlen(p) == strlen(".avx2"))
		return;

	if (__builtin_cpu_supports("avx2")) {
		char new_path[PATH_MAX + sizeof(".avx2")];

		snprintf(new_path, PATH_MAX + sizeof(".avx2"), "%s.avx2", exe);
		execve(new_path, argv, environ);
		perror("Can't run AVX2 build, using non-AVX2 version");
	}
}
#else
void arch_avx2_exec(char **argv) { (void)argv; }
#endif

// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * isolation.c - Self isolation helpers
 *
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <sched.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "util.h"
#include "seccomp.h"
#include "passt.h"
#include "isolation.h"

/**
 * drop_caps() - Drop capabilities we might have except for CAP_NET_BIND_SERVICE
 */
void drop_caps(void)
{
	int i;

	for (i = 0; i < 64; i++) {
		if (i == CAP_NET_BIND_SERVICE)
			continue;

		prctl(PR_CAPBSET_DROP, i, 0, 0, 0);
	}
}

/**
 * drop_root() - Switch to given UID and GID
 * @uid:	User ID to switch to
 * @gid:	Group ID to switch to
 */
void drop_root(uid_t uid, gid_t gid)
{
	if (setgroups(0, NULL)) {
		/* If we don't start with CAP_SETGID, this will EPERM */
		if (errno != EPERM) {
			err("Can't drop supplementary groups: %s",
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (!setgid(gid) && !setuid(uid))
		return;

	err("Can't change user/group, exiting");
	exit(EXIT_FAILURE);
}

/**
 * sandbox() - Unshare IPC, mount, PID, UTS, and user namespaces, "unmount" root
 *
 * Return: negative error code on failure, zero on success
 */
int sandbox(struct ctx *c)
{
	int flags = CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS;

	if (!c->netns_only) {
		if (c->pasta_userns_fd == -1)
			flags |= CLONE_NEWUSER;
		else
			setns(c->pasta_userns_fd, CLONE_NEWUSER);
	}

	c->pasta_userns_fd = -1;

	/* If we run in foreground, we have no chance to actually move to a new
	 * PID namespace. For passt, use CLONE_NEWPID anyway, in case somebody
	 * ever gets around seccomp profiles -- there's no harm in passing it.
	 */
	if (!c->foreground || c->mode == MODE_PASST)
		flags |= CLONE_NEWPID;

	if (unshare(flags)) {
		perror("unshare");
		return -errno;
	}

	if (mount("", "/", "", MS_UNBINDABLE | MS_REC, NULL)) {
		perror("mount /");
		return -errno;
	}

	if (mount("", TMPDIR, "tmpfs",
		  MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RDONLY,
		  "nr_inodes=2,nr_blocks=0")) {
		perror("mount tmpfs");
		return -errno;
	}

	if (chdir(TMPDIR)) {
		perror("chdir");
		return -errno;
	}

	if (syscall(SYS_pivot_root, ".", ".")) {
		perror("pivot_root");
		return -errno;
	}

	if (umount2(".", MNT_DETACH | UMOUNT_NOFOLLOW)) {
		perror("umount2");
		return -errno;
	}

	drop_caps();	/* Relative to the new user namespace this time. */

	return 0;
}

/**
 * seccomp() - Set up seccomp filters depending on mode, won't return on failure
 * @c:		Execution context
 */
void seccomp(const struct ctx *c)
{
	struct sock_fprog prog;

	if (c->mode == MODE_PASST) {
		prog.len = (unsigned short)ARRAY_SIZE(filter_passt);
		prog.filter = filter_passt;
	} else {
		prog.len = (unsigned short)ARRAY_SIZE(filter_pasta);
		prog.filter = filter_pasta;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl");
		exit(EXIT_FAILURE);
	}
}

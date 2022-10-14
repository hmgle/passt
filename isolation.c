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
/**
 * DOC: Theory of Operation
 *
 * For security the passt/pasta process performs a number of
 * self-isolations steps, dropping capabilities, setting namespaces
 * and otherwise minimising the impact we can have on the system at
 * large if we were compromised.
 *
 * Obviously we can't isolate ourselves from resources before we've
 * done anything we need to do with those resources, so we have
 * multiple stages of self-isolation.  In order these are:
 *
 * 1. isolate_initial()
 * ====================
 *
 * Executed immediately after startup, drops capabilities we don't
 * need at any point during execution (or which we gain back when we
 * need by joining other namespaces).
 *
 * 2. isolate_user()
 * =================
 *
 * Executed once we know what user and user namespace we want to
 * operate in.  Sets our final UID & GID, and enters the correct user
 * namespace.
 *
 * 3. isolate_prefork()
 * ====================
 *
 * Executed after all setup, but before daemonising (fork()ing into
 * the background).  Uses mount namespace and pivot_root() to remove
 * our access to the filesystem.
 *
 * 4. isolate_postfork()
 * =====================
 *
 * Executed immediately after daemonizing, but before entering the
 * actual packet forwarding phase of operation.  Or, if not
 * daemonizing, immediately after isolate_prefork().  Uses seccomp()
 * to restrict ourselves to the handful of syscalls we need during
 * runtime operation.
 */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <sched.h>
#include <stdbool.h>
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
#include "log.h"
#include "isolation.h"

/**
 * drop_caps() - Drop capabilities we might have except for CAP_NET_BIND_SERVICE
 */
static void drop_caps(void)
{
	int i;

	for (i = 0; i < 64; i++) {
		if (i == CAP_NET_BIND_SERVICE)
			continue;

		prctl(PR_CAPBSET_DROP, i, 0, 0, 0);
	}
}

/**
 * isolate_initial() - Early, config independent self isolation
 *
 * Should:
 *  - drop unneeded capabilities
 * Musn't:
 *  - remove filesytem access (we need to access files during setup)
 */
void isolate_initial(void)
{
	drop_caps();
}

/**
 * isolate_user() - Switch to final UID/GID and move into userns
 * @uid:	User ID to run as (in original userns)
 * @gid:	Group ID to run as (in original userns)
 * @use_userns:	Whether to join or create a userns
 * @userns:	userns path to enter, may be empty
 *
 * Should:
 *  - set our final UID and GID
 *  - enter our final user namespace
 * Mustn't:
 *  - remove filesystem access (we need that for further setup)
 */
void isolate_user(uid_t uid, gid_t gid, bool use_userns, const char *userns)
{
	/* First set our UID & GID in the original namespace */
	if (setgroups(0, NULL)) {
		/* If we don't have CAP_SETGID, this will EPERM */
		if (errno != EPERM) {
			err("Can't drop supplementary groups: %s",
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (setgid(gid) != 0) {
		err("Can't set GID to %u: %s", gid, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setuid(uid) != 0) {
		err("Can't set UID to %u: %s", uid, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (*userns) { /* If given a userns, join it */
		int ufd;

		ufd = open(userns, O_RDONLY | O_CLOEXEC);
		if (ufd < 0) {
			err("Couldn't open user namespace %s: %s",
			    userns, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (setns(ufd, CLONE_NEWUSER) != 0) {
			err("Couldn't enter user namespace %s: %s",
			    userns, strerror(errno));
			exit(EXIT_FAILURE);
		}

		close(ufd);
	} else if (use_userns) { /* Create and join a new userns */
		char uidmap[BUFSIZ];
		char gidmap[BUFSIZ];

		if (unshare(CLONE_NEWUSER) != 0) {
			err("Couldn't create user namespace: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* Configure user and group mappings */
		snprintf(uidmap, BUFSIZ, "0 %u 1", uid);
		snprintf(gidmap, BUFSIZ, "0 %u 1", gid);

		if (write_file("/proc/self/uid_map", uidmap) ||
		    write_file("/proc/self/setgroups", "deny") ||
		    write_file("/proc/self/gid_map", gidmap)) {
			warn("Couldn't configure user namespace");
		}
	}
}

/**
 * isolate_prefork() - Self isolation before daemonizing
 * @c:		Execution context
 *
 * Return: negative error code on failure, zero on success
 *
 * Should:
 *  - Move us to our own IPC and UTS namespaces
 *  - Move us to a mount namespace with only an empty directory
 *  - Drop unneeded capabilities (in the new user namespace)
 * Mustn't:
 *  - Remove syscalls we need to daemonise
 */
int isolate_prefork(struct ctx *c)
{
	int flags = CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS;

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
 * isolate_postfork() - Self isolation after daemonizing
 * @c:		Execution context
 *
 * Should:
 *  - disable core dumps
 *  - limit to a minimal set of syscalls
 */
void isolate_postfork(const struct ctx *c)
{
	struct sock_fprog prog;

	prctl(PR_SET_DUMPABLE, 0);

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

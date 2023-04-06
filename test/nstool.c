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
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/un.h>
#include <sched.h>
#include <linux/capability.h>

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

#define for_each_nst(_nst, _flags)				\
	for ((_nst) = &nstypes[0];				\
	     ((_nst) - nstypes) < ARRAY_SIZE(nstypes);		\
	     (_nst)++)						\
		if ((_flags) & (_nst)->flag)

#define for_every_nst(_nst)	for_each_nst(_nst, INT_MAX)

#define NSTOOL_MAGIC	0x7570017575601d75ULL

struct holder_info {
	uint64_t magic;
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
	    "      -p          Print just the holder's PID as seen by the caller\n"
	    "      -w          Retry connecting to SOCK until it is ready\n"
	    "  nstool exec [--keep-caps] SOCK [COMMAND [ARGS...]]\n"
	    "    Execute command or shell in the namespaces of the nstool hold\n"
	    "    with control socket at SOCK\n"
	    "      --keep-caps Give all possible capabilities to COMMAND via\n"
	    "                  the ambient capability mask\n"
	    "  nstool stop SOCK\n"
	    "    Instruct the nstool hold with control socket at SOCK to\n"
	    "    terminate.\n");
}

static int connect_ctl(const char *sockpath, bool wait,
		       struct holder_info *info,
		       struct ucred *peercred)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNIX);
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

	if (info->magic != NSTOOL_MAGIC)
		die("Control socket %s doesn't appear to belong to nstool\n",
		    sockpath);

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
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNIX);
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

	info.magic = NSTOOL_MAGIC;
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
	const struct ns_type *nst;
	int flags = 0;

	for_every_nst(nst) {
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
	const struct ns_type *nst;
	bool first = true;

	for_each_nst(nst, flags) {
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

static int openns(const char *fmt, ...)
{
	char nspath[PATH_MAX];
	va_list ap;
	int fd;

	va_start(ap, fmt);
	if (vsnprintf(nspath, sizeof(nspath), fmt, ap) >= PATH_MAX)
		die("Truncated path \"%s\"\n", nspath);
	va_end(ap);

	fd = open(nspath, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open() %s: %s\n", nspath, strerror(errno));

	return fd;
}

static void wait_for_child(pid_t pid)
{
	int status;

	/* Match the child's exit status, if possible */
	for (;;) {
		pid_t rc;

		rc = waitpid(pid, &status, WUNTRACED);
		if (rc < 0)
			die("waitpid() on %d: %s\n", pid, strerror(errno));
		if (rc != pid)
			die("waitpid() on %d returned %d", pid, rc);
		if (WIFSTOPPED(status)) {
			/* Stop the parent to patch */
			kill(getpid(), SIGSTOP);
			/* We must have resumed, resume the child */
			kill(pid, SIGCONT);
			continue;
		}

		break;
	}

	if (WIFEXITED(status))
		exit(WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		kill(getpid(), WTERMSIG(status));

	die("Unexpected status for child %d\n", pid);
}

static void caps_to_ambient(void)
{
	/* Use raw system calls to avoid the overly complex caps
	 * libraries. */
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct payload[_LINUX_CAPABILITY_U32S_3] =
		{{ 0 }};
	uint64_t effective, cap;

	if (syscall(SYS_capget, &header, payload) < 0)
		die("capget(): %s\n", strerror(errno));

	/* First make caps inheritable */
	payload[0].inheritable = payload[0].permitted;
	payload[1].inheritable = payload[1].permitted;

	if (syscall(SYS_capset, &header, payload) < 0)
		die("capset(): %s\n", strerror(errno));

	effective = ((uint64_t)payload[1].effective << 32) | (uint64_t)payload[0].effective;

	for (cap = 0; cap < (sizeof(effective) * 8); cap++) {
		/* Skip non-existent caps */
		if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) < 0)
			continue;

		if ((effective & (1 << cap))
		    && prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) < 0)
			die("prctl(PR_CAP_AMBIENT): %s\n", strerror(errno));
	}
}

static void cmd_exec(int argc, char *argv[])
{
	enum {
		OPT_EXEC_KEEPCAPS = CHAR_MAX + 1,
	};
	const struct option options[] = {
		{"keep-caps",	no_argument, 	NULL,	OPT_EXEC_KEEPCAPS },
		{ 0 },
	};
	const char *shargs[] = { NULL, NULL };
	const char *sockpath = argv[1];
	int nfd[ARRAY_SIZE(nstypes)];
	const char *optstring = "";
	const struct ns_type *nst;
	int ctlfd, flags, opt, rc;
	const char *const *xargs;
	bool keepcaps = false;
	struct ucred peercred;
	const char *exe;
	pid_t xpid;

	do {
		opt = getopt_long(argc, argv, optstring, options, NULL);

		switch (opt) {
		case OPT_EXEC_KEEPCAPS:
			keepcaps = true;
			break;
		case -1:
			break;
		default:
			usage();
		}
	} while (opt != -1);

	if (argc < optind + 1)
		usage();

	sockpath = argv[optind];

	ctlfd = connect_ctl(sockpath, false, NULL, &peercred);

	flags = detect_namespaces(peercred.pid);

	for_each_nst(nst, flags) {
		int *fd = &nfd[nst - nstypes];
		*fd = openns("/proc/%d/ns/%s", peercred.pid, nst->name);
	}

	/* First pass, will get things where we need the privileges of
	 * the initial userns */
	for_each_nst(nst, flags) {
		int fd = nfd[nst - nstypes];

		rc = setns(fd, nst->flag);
		if (rc == 0) {
			flags &= ~nst->flag;
		}
	}

	/* Second pass, will get things where we need the privileges
	 * of the target userns */
	for_each_nst(nst, flags) {
		int fd = nfd[nst - nstypes];

		rc = setns(fd, nst->flag);
		if (rc < 0)
			die("setns() type %s: %s\n",
			    nst->name, strerror(errno));
	}

	/* Fork to properly enter PID namespace */
	xpid = fork();
	if (xpid < 0)
		die("fork(): %s\n", strerror(errno));

	if (xpid > 0) {
		/* Close the control socket so the waiting parent
		 * doesn't block the holder */
		close(ctlfd);
		wait_for_child(xpid);
	}

	/* CHILD */
	if (argc > optind + 1) {
		exe = argv[optind + 1];
		xargs = (const char * const*)(argv + optind + 1);
	} else {
		exe = getenv("SHELL");
		if (!exe)
			exe = "/bin/sh";

		shargs[0] = exe;

		xargs = shargs;
	}

	if (keepcaps)
		caps_to_ambient();

	rc = execvp(exe, (char *const *)xargs);
	if (rc < 0)
		die("execv() %s: %s\n", exe, strerror(errno));
	die("Returned from exec()\n");
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
	else if (strcmp(subcmd, "exec") == 0)
		cmd_exec(argc - 1, argv + 1);
	else if (strcmp(subcmd, "stop") == 0)
		cmd_stop(argc - 1, argv + 1);
	else
		usage();

	exit(0);
}

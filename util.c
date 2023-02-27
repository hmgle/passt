// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * util.c - Convenience helpers
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>

#include "util.h"
#include "passt.h"
#include "packet.h"
#include "lineread.h"
#include "log.h"

#define IPV6_NH_OPT(nh)							\
	((nh) == 0   || (nh) == 43  || (nh) == 44  || (nh) == 50  ||	\
	 (nh) == 51  || (nh) == 60  || (nh) == 135 || (nh) == 139 ||	\
	 (nh) == 140 || (nh) == 253 || (nh) == 254)

/**
 * ipv6_l4hdr() - Find pointer to L4 header in IPv6 packet and extract protocol
 * @p:		Packet pool, packet number @index has IPv6 header at @offset
 * @index:	Index of packet in pool
 * @offset:	Pre-calculated IPv6 header offset
 * @proto:	Filled with L4 protocol number
 * @dlen:	Data length (payload excluding header extensions), set on return
 *
 * Return: pointer to L4 header, NULL if not found
 */
char *ipv6_l4hdr(const struct pool *p, int index, size_t offset, uint8_t *proto,
		 size_t *dlen)
{
	struct ipv6_opt_hdr *o;
	struct ipv6hdr *ip6h;
	char *base;
	int hdrlen;
	uint8_t nh;

	base = packet_get(p, index, 0, 0, NULL);
	ip6h = packet_get(p, index, offset, sizeof(*ip6h), dlen);
	if (!ip6h)
		return NULL;

	offset += sizeof(*ip6h);

	nh = ip6h->nexthdr;
	if (!IPV6_NH_OPT(nh))
		goto found;

	while ((o = packet_get_try(p, index, offset, sizeof(*o), dlen))) {
		nh = o->nexthdr;
		hdrlen = (o->hdrlen + 1) * 8;

		if (IPV6_NH_OPT(nh))
			offset += hdrlen;
		else
			goto found;
	}

	return NULL;

found:
	if (nh == 59)
		return NULL;

	*proto = nh;
	return base + offset;
}

/**
 * sock_l4() - Create and bind socket for given L4, add to epoll list
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @proto:	Protocol number
 * @bind_addr:	Address for binding, NULL for any
 * @ifname:	Interface for binding, NULL for any
 * @port:	Port, host order
 * @data:	epoll reference portion for protocol handlers
 *
 * Return: newly created socket, -1 on error
 */
int sock_l4(const struct ctx *c, int af, uint8_t proto,
	    const void *bind_addr, const char *ifname, uint16_t port,
	    uint32_t data)
{
	union epoll_ref ref = { .r.proto = proto, .r.p.data = data };
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		{ 0 }, { 0 },
	};
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		0, IN6ADDR_ANY_INIT, 0,
	};
	const struct sockaddr *sa;
	bool dual_stack = false;
	struct epoll_event ev;
	int fd, sl, y = 1;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	    proto != IPPROTO_ICMP && proto != IPPROTO_ICMPV6)
		return -1;	/* Not implemented. */

	if (af == AF_UNSPEC) {
		if (!DUAL_STACK_SOCKETS || bind_addr)
			return -1;
		dual_stack = true;
		af = AF_INET6;
	}

	if (proto == IPPROTO_TCP)
		fd = socket(af, SOCK_STREAM | SOCK_NONBLOCK, proto);
	else
		fd = socket(af, SOCK_DGRAM | SOCK_NONBLOCK, proto);

	if (fd < 0) {
		warn("L4 socket: %s", strerror(errno));
		return -1;
	}

	if (fd > SOCKET_MAX) {
		close(fd);
		return -1;
	}

	ref.r.s = fd;

	if (af == AF_INET) {
		if (bind_addr)
			addr4.sin_addr.s_addr = *(in_addr_t *)bind_addr;
		else
			addr4.sin_addr.s_addr = htonl(INADDR_ANY);

		sa = (const struct sockaddr *)&addr4;
		sl = sizeof(addr4);
	} else {
		if (bind_addr) {
			addr6.sin6_addr = *(struct in6_addr *)bind_addr;

			if (!memcmp(bind_addr, &c->ip6.addr_ll,
			    sizeof(c->ip6.addr_ll)))
				addr6.sin6_scope_id = c->ifi6;
		} else {
			addr6.sin6_addr = in6addr_any;
		}

		sa = (const struct sockaddr *)&addr6;
		sl = sizeof(addr6);

		if (!dual_stack)
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
				       &y, sizeof(y)))
				debug("Failed to set IPV6_V6ONLY on socket %i",
				      fd);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)))
		debug("Failed to set SO_REUSEADDR on socket %i", fd);

	if (ifname) {
		/* Supported since kernel version 5.7, commit c427bfec18f2
		 * ("net: core: enable SO_BINDTODEVICE for non-root users"). If
		 * it's unsupported, don't bind the socket at all, because the
		 * user might rely on this to filter incoming connections.
		 */
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
			       ifname, strlen(ifname))) {
			warn("Can't bind socket for %s port %u to %s, closing",
			     ip_proto_str[proto], port, ifname);
			close(fd);
			return -1;
		}
	}

	if (bind(fd, sa, sl) < 0) {
		/* We'll fail to bind to low ports if we don't have enough
		 * capabilities, and we'll fail to bind on already bound ports,
		 * this is fine. This might also fail for ICMP because of a
		 * broken SELinux policy, see icmp_tap_handler().
		 */
		if (proto != IPPROTO_ICMP && proto != IPPROTO_ICMPV6) {
			close(fd);
			return -1;
		}
	}

	if (proto == IPPROTO_TCP && listen(fd, 128) < 0) {
		warn("TCP socket listen: %s", strerror(errno));
		close(fd);
		return -1;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = ref.u64;
	if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		warn("L4 epoll_ctl: %s", strerror(errno));
		return -1;
	}

	return fd;
}

/**
 * sock_probe_mem() - Check if setting high SO_SNDBUF and SO_RCVBUF is allowed
 * @c:		Execution context
 */
void sock_probe_mem(struct ctx *c)
{
	int v = INT_MAX / 2, s;
	socklen_t sl;

	if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		c->low_wmem = c->low_rmem = 1;
		return;
	}

	sl = sizeof(v);
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v))	||
	    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, &sl) ||
	    (size_t)v < SNDBUF_BIG)
		c->low_wmem = 1;

	v = INT_MAX / 2;
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v))	||
	    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &sl) ||
	    (size_t)v < RCVBUF_BIG)
		c->low_rmem = 1;

	close(s);
}


/**
 * timespec_diff_ms() - Report difference in milliseconds between two timestamps
 * @a:		Minuend timestamp
 * @b:		Subtrahend timestamp
 *
 * Return: difference in milliseconds
 */
int timespec_diff_ms(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_nsec < b->tv_nsec) {
		return (b->tv_nsec - a->tv_nsec) / 1000000 +
		       (a->tv_sec - b->tv_sec - 1) * 1000;
	}

	return (a->tv_nsec - b->tv_nsec) / 1000000 +
	       (a->tv_sec - b->tv_sec) * 1000;
}

/**
 * bitmap_set() - Set single bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to set
 */
void bitmap_set(uint8_t *map, int bit)
{
	unsigned long *word = (unsigned long *)map + BITMAP_WORD(bit);

	*word |= BITMAP_BIT(bit);
}

/**
 * bitmap_clear() - Clear single bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to clear
 */
void bitmap_clear(uint8_t *map, int bit)
{
	unsigned long *word = (unsigned long *)map + BITMAP_WORD(bit);

	*word &= ~BITMAP_BIT(bit);
}

/**
 * bitmap_isset() - Check for set bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to check
 *
 * Return: one if given bit is set, zero if it's not
 */
int bitmap_isset(const uint8_t *map, int bit)
{
	unsigned long *word = (unsigned long *)map + BITMAP_WORD(bit);

	return !!(*word & BITMAP_BIT(bit));
}

/**
 * procfs_scan_listen() - Set bits for listening TCP or UDP sockets from procfs
 * @proto:	IPPROTO_TCP or IPPROTO_UDP
 * @ip_version:	IP version, V4 or V6
 * @ns:		Use saved file descriptors for namespace if set
 * @map:	Bitmap where numbers of ports in listening state will be set
 * @exclude:	Bitmap of ports to exclude from setting (and clear)
 *
 * #syscalls:pasta lseek
 * #syscalls:pasta ppc64le:_llseek ppc64:_llseek armv6l:_llseek armv7l:_llseek
 */
void procfs_scan_listen(struct ctx *c, uint8_t proto, int ip_version, int ns,
			uint8_t *map, uint8_t *exclude)
{
	char *path, *line;
	struct lineread lr;
	unsigned long port;
	unsigned int state;
	int *fd;

	if (proto == IPPROTO_TCP) {
		fd = &c->proc_net_tcp[ip_version][ns];
		if (ip_version == V4)
			path = "/proc/net/tcp";
		else
			path = "/proc/net/tcp6";
	} else {
		fd = &c->proc_net_udp[ip_version][ns];
		if (ip_version == V4)
			path = "/proc/net/udp";
		else
			path = "/proc/net/udp6";
	}

	if (*fd != -1) {
		if (lseek(*fd, 0, SEEK_SET)) {
			warn("lseek() failed on %s: %s", path, strerror(errno));
			return;
		}
	} else if ((*fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
		return;
	}

	lineread_init(&lr, *fd);
	lineread_get(&lr, &line); /* throw away header */
	while (lineread_get(&lr, &line) > 0) {
		/* NOLINTNEXTLINE(cert-err34-c): != 2 if conversion fails */
		if (sscanf(line, "%*u: %*x:%lx %*x:%*x %x", &port, &state) != 2)
			continue;

		/* See enum in kernel's include/net/tcp_states.h */
		if ((proto == IPPROTO_TCP && state != 0x0a) ||
		    (proto == IPPROTO_UDP && state != 0x07))
			continue;

		if (bitmap_isset(exclude, port))
			bitmap_clear(map, port);
		else
			bitmap_set(map, port);
	}
}

/**
 * ns_enter() - Enter configured user (unless already joined) and network ns
 * @c:		Execution context
 *
 * Return: 0, won't return on failure
 *
 * #syscalls:pasta setns
 */
int ns_enter(const struct ctx *c)
{
	if (setns(c->pasta_netns_fd, CLONE_NEWNET))
		exit(EXIT_FAILURE);

	return 0;
}

/**
 * pid_file() - Write PID to file, if requested to do so, and close it
 * @fd:		Open PID file descriptor, closed on exit, -1 to skip writing it
 * @pid:	PID value to write
 */
void write_pidfile(int fd, pid_t pid)
{
	char pid_buf[12];
	int n;

	if (fd == -1)
		return;

	n = snprintf(pid_buf, sizeof(pid_buf), "%i\n", pid);

	if (write(fd, pid_buf, n) < 0) {
		perror("PID file write");
		exit(EXIT_FAILURE);
	}

	close(fd);
}

/**
 * __daemon() - daemon()-like function writing PID file before parent exits
 * @pidfile_fd:	Open PID file descriptor
 * @devnull_fd:	Open file descriptor for /dev/null
 *
 * Return: child PID on success, won't return on failure
 */
int __daemon(int pidfile_fd, int devnull_fd)
{
	pid_t pid = fork();

	if (pid == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if (pid) {
		write_pidfile(pidfile_fd, pid);
		exit(EXIT_SUCCESS);
	}

	errno = 0;

	setsid();

	dup2(devnull_fd, STDIN_FILENO);
	dup2(devnull_fd, STDOUT_FILENO);
	dup2(devnull_fd, STDERR_FILENO);
	close(devnull_fd);

	if (errno)
		exit(EXIT_FAILURE);

	return 0;
}

/**
 * fls() - Find last (most significant) bit set in word
 * @x:		Word
 *
 * Return: position of most significant bit set, starting from 0, -1 if none
 */
int fls(unsigned long x)
{
	int y = 0;

	if (!x)
		return -1;

	while (x >>= 1)
		y++;

	return y;
}

/**
 * write_file() - Replace contents of file with a string
 * @path:	File to write
 * @buf:	String to write
 *
 * Return: 0 on success, -1 on any error
 */
int write_file(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	size_t len = strlen(buf);

	if (fd < 0) {
		warn("Could not open %s: %s", path, strerror(errno));
		return -1;
	}

	while (len) {
		ssize_t rc = write(fd, buf, len);

		if (rc <= 0) {
			warn("Couldn't write to %s: %s", path, strerror(errno));
			break;
		}

		buf += rc;
		len -= rc;
	}

	close(fd);
	return len == 0 ? 0 : -1;
}

#ifdef __ia64__
/* Needed by do_clone() below: glibc doesn't export the prototype of __clone2(),
 * use the description from clone(2).
 */
int __clone2(int (*fn)(void *), void *stack_base, size_t stack_size, int flags,
	     void *arg, ... /* pid_t *parent_tid, struct user_desc *tls,
	     pid_t *child_tid */ );
#endif

/**
 * do_clone() - Wrapper of __clone2() for ia64, clone() for other architectures
 * @fn:		Entry point for child
 * @stack_area:	Stack area for child: we'll point callees to the middle of it
 * @stack_size:	Total size of stack area, passed to callee divided by two
 * @flags:	clone() system call flags
 * @arg:	Argument to @fn
 *
 * Return: thread ID of child, -1 on failure
 */
int do_clone(int (*fn)(void *), char *stack_area, size_t stack_size, int flags,
	     void *arg)
{
#ifdef __ia64__
	return __clone2(fn, stack_area + stack_size / 2, stack_size / 2,
			flags, arg);
#else
	return clone(fn, stack_area + stack_size / 2, flags, arg);
#endif
}

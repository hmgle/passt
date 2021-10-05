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

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "util.h"
#include "passt.h"

#define logfn(name, level)						\
void name(const char *format, ...) {					\
	char ts[sizeof("Mmm dd hh:mm:ss.")];				\
	struct timespec tp;						\
	struct tm *tm;							\
	va_list args;							\
									\
	if (setlogmask(0) & LOG_MASK(LOG_DEBUG)) {			\
		clock_gettime(CLOCK_REALTIME, &tp);			\
		tm = gmtime(&tp.tv_sec);				\
		strftime(ts, sizeof(ts), "%b %d %T.", tm);		\
									\
		fprintf(stderr, "%s%04lu: ", ts,			\
			tp.tv_nsec / (100 * 1000));			\
	}								\
									\
	va_start(args, format);						\
	vsyslog(level, format, args);					\
	va_end(args);							\
									\
	if (setlogmask(0) & LOG_MASK(LOG_DEBUG) ||			\
	    setlogmask(0) == LOG_MASK(LOG_EMERG)) {			\
		va_start(args, format);					\
		vfprintf(stderr, format, args); 			\
		va_end(args);						\
		if (format[strlen(format)] != '\n')			\
			fprintf(stderr, "\n");				\
	}								\
}

logfn(err,   LOG_ERR)
logfn(warn,  LOG_WARNING)
logfn(info,  LOG_INFO)
logfn(debug, LOG_DEBUG)

/**
 * ipv6_l4hdr() - Find pointer to L4 header in IPv6 packet and extract protocol
 * @ip6h:	IPv6 header
 * @proto:	Filled with L4 protocol number
 *
 * Return: pointer to L4 header, NULL if not found
 */
char *ipv6_l4hdr(struct ipv6hdr *ip6h, uint8_t *proto)
{
	int offset, len, hdrlen;
	struct ipv6_opt_hdr *o;
	uint8_t nh;

	len = ntohs(ip6h->payload_len);
	offset = 0;

	while (offset < len) {
		if (!offset) {
			nh = ip6h->nexthdr;
			hdrlen = sizeof(struct ipv6hdr);
		} else {
			o = (struct ipv6_opt_hdr *)(((char *)ip6h) + offset);
			nh = o->nexthdr;
			hdrlen = (o->hdrlen + 1) * 8;
		}

		if (nh == 59)
			return NULL;

		if (nh == 0   || nh == 43  || nh == 44  || nh == 50  ||
		    nh == 51  || nh == 60  || nh == 135 || nh == 139 ||
		    nh == 140 || nh == 253 || nh == 254) {
			offset += hdrlen;
		} else {
			*proto = nh;
			return (char *)(ip6h + 1) + offset;
		}
	}

	return NULL;
}

/**
 * sock_l4() - Create and bind socket for given L4, add to epoll list
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @proto:	Protocol number
 * @port:	Port, host order
 * @bind_type:	Type of address for binding
 * @data:	epoll reference portion for protocol handlers
 *
 * Return: newly created socket, -1 on error
 */
int sock_l4(struct ctx *c, int af, uint8_t proto, uint16_t port,
	    enum bind_type bind_addr, uint32_t data)
{
	union epoll_ref ref = { .proto = proto, .data = data };
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
	};
	const struct sockaddr *sa;
	struct epoll_event ev;
	int fd, sl, one = 1;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	    proto != IPPROTO_ICMP && proto != IPPROTO_ICMPV6)
		return -1;	/* Not implemented. */

	if (proto == IPPROTO_TCP)
		fd = socket(af, SOCK_STREAM | SOCK_NONBLOCK, proto);
	else
		fd = socket(af, SOCK_DGRAM | SOCK_NONBLOCK, proto);
	if (fd < 0) {
		perror("L4 socket");
		return -1;
	}
	ref.s = fd;

	if (af == AF_INET) {
		if (bind_addr == BIND_LOOPBACK)
			addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		else if (bind_addr == BIND_EXT)
			addr4.sin_addr.s_addr = c->addr4;
		else
			addr4.sin_addr.s_addr = htonl(INADDR_ANY);

		sa = (const struct sockaddr *)&addr4;
		sl = sizeof(addr4);
	} else {
		if (bind_addr == BIND_LOOPBACK) {
			addr6.sin6_addr = in6addr_loopback;
		} else if (bind_addr == BIND_EXT) {
			addr6.sin6_addr = c->addr6;
		} else if (bind_addr == BIND_LL) {
			addr6.sin6_addr = c->addr6_ll;
			addr6.sin6_scope_id = if_nametoindex(c->ifn);
		} else {
			addr6.sin6_addr = in6addr_any;
		}

		sa = (const struct sockaddr *)&addr6;
		sl = sizeof(addr6);

		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if (bind(fd, sa, sl) < 0) {
		/* We'll fail to bind to low ports if we don't have enough
		 * capabilities, and we'll fail to bind on already bound ports,
		 * this is fine. This might also fail for ICMP because of a
		 * broken SELinux policy, see icmp_tap_handler().
		 */
		if (proto != IPPROTO_ICMP && proto != IPPROTO_ICMPV6) {
			close(fd);
			return 0;
		}
	}

	if (proto == IPPROTO_TCP && listen(fd, 128) < 0) {
		perror("TCP socket listen");
		close(fd);
		return -1;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = ref.u64;
	if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		perror("L4 epoll_ctl");
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
	    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, &sl) || v < SNDBUF_BIG)
		c->low_wmem = 1;

	v = INT_MAX / 2;
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v))	||
	    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &sl) || v < RCVBUF_BIG)
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
int timespec_diff_ms(struct timespec *a, struct timespec *b)
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
	map[bit / 8] |= 1 << (bit % 8);
}

/**
 * bitmap_set() - Clear single bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to clear
 */
void bitmap_clear(uint8_t *map, int bit)
{
	map[bit / 8] &= ~(1 << (bit % 8));
}

/**
 * bitmap_isset() - Check for set bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to check
 *
 * Return: non-zero if given bit is set, zero if it's not
 */
int bitmap_isset(uint8_t *map, int bit)
{
	return map[bit / 8] & (1 << bit % 8);
}

/**
 * procfs_scan_listen() - Set bits for listening TCP or UDP sockets from procfs
 * @name:	Corresponding name of file under /proc/net/
 * @map:	Bitmap where numbers of ports in listening state will be set
 * @exclude:	Bitmap of ports to exclude from setting (and clear)
 */
void procfs_scan_listen(char *name, uint8_t *map, uint8_t *exclude)
{
	char line[200], path[PATH_MAX];
	unsigned long port;
	unsigned int state;
	FILE *fp;

	snprintf(path, PATH_MAX, "/proc/net/%s", name);
	if (!(fp = fopen(path, "r")))
		return;

	fgets(line, sizeof(line), fp);
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%*u: %*x:%lx %*x:%*x %x", &port, &state) != 2)
			continue;

		/* See enum in kernel's include/net/tcp_states.h */
		if ((strstr(name, "tcp") && state != 0x0a) ||
		    (strstr(name, "udp") && state != 0x07))
			continue;

		if (bitmap_isset(exclude, port))
			bitmap_clear(map, port);
		else
			bitmap_set(map, port);
	}

	fclose(fp);
}

/**
 * ns_enter() - Enter user and network namespaces of process with given PID
 * @target_pid:		Process PID
 *
 * Return: 0 on success, -1 on failure
 */
int ns_enter(int target_pid)
{
	char ns[PATH_MAX];
	int fd;

	snprintf(ns, PATH_MAX, "/proc/%i/ns/user", target_pid);
	if ((fd = open(ns, O_RDONLY)) < 0 || setns(fd, 0))
		goto fail;
	close(fd);

	snprintf(ns, PATH_MAX, "/proc/%i/ns/net", target_pid);
	if ((fd = open(ns, O_RDONLY)) < 0 || setns(fd, 0))
		goto fail;
	close(fd);

	return 0;

fail:
	if (fd != -1)
		close(fd);

	return -1;
}

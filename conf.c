// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * conf.c - Configuration settings and option parsing
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "util.h"
#include "passt.h"
#include "netlink.h"
#include "udp.h"
#include "tcp.h"
#include "pasta.h"
#include "lineread.h"
#include "isolation.h"
#include "log.h"
#include "child.h"

/**
 * get_bound_ports() - Get maps of ports with bound sockets
 * @c:		Execution context
 * @ns:		If set, set bitmaps for ports to tap/ns -- to init otherwise
 * @proto:	Protocol number (IPPROTO_TCP or IPPROTO_UDP)
 */
void get_bound_ports(struct ctx *c, int ns, uint8_t proto)
{
	uint8_t *udp_map, *udp_excl, *tcp_map, *tcp_excl;

	if (ns) {
		udp_map = c->udp.fwd_in.f.map;
		udp_excl = c->udp.fwd_out.f.map;
		tcp_map = c->tcp.fwd_in.map;
		tcp_excl = c->tcp.fwd_out.map;
	} else {
		udp_map = c->udp.fwd_out.f.map;
		udp_excl = c->udp.fwd_in.f.map;
		tcp_map = c->tcp.fwd_out.map;
		tcp_excl = c->tcp.fwd_in.map;
	}

	if (proto == IPPROTO_UDP) {
		memset(udp_map, 0, PORT_BITMAP_SIZE);
		procfs_scan_listen(c, IPPROTO_UDP, V4, ns, udp_map, udp_excl);
		procfs_scan_listen(c, IPPROTO_UDP, V6, ns, udp_map, udp_excl);

		procfs_scan_listen(c, IPPROTO_TCP, V4, ns, udp_map, udp_excl);
		procfs_scan_listen(c, IPPROTO_TCP, V6, ns, udp_map, udp_excl);
	} else if (proto == IPPROTO_TCP) {
		memset(tcp_map, 0, PORT_BITMAP_SIZE);
		procfs_scan_listen(c, IPPROTO_TCP, V4, ns, tcp_map, tcp_excl);
		procfs_scan_listen(c, IPPROTO_TCP, V6, ns, tcp_map, tcp_excl);
	}
}

/**
 * struct get_bound_ports_ns_arg - Arguments for get_bound_ports_ns()
 * @c:		Execution context
 * @proto:	Protocol number (IPPROTO_TCP or IPPROTO_UDP)
 */
struct get_bound_ports_ns_arg {
	struct ctx *c;
	uint8_t proto;
};

/**
 * get_bound_ports_ns() - Get maps of ports in namespace with bound sockets
 * @arg:	See struct get_bound_ports_ns_arg
 *
 * Return: 0
 */
static int get_bound_ports_ns(void *arg)
{
	struct get_bound_ports_ns_arg *a = (struct get_bound_ports_ns_arg *)arg;
	struct ctx *c = a->c;

	if (!c->pasta_netns_fd || ns_enter(c))
		return 0;

	get_bound_ports(c, 1, a->proto);

	return 0;
}

/**
 * next_chunk - Return the next piece of a string delimited by a character
 * @s:		String to search
 * @c:		Delimiter character
 *
 * Return: If another @c is found in @s, returns a pointer to the
 *	   character *after* the delimiter, if no further @c is in @s,
 *	   return NULL
 */
static char *next_chunk(const char *s, char c)
{
	char *sep = strchr(s, c);
	return sep ? sep + 1 : NULL;
}

/**
 * port_range - Represents a non-empty range of ports
 * @first:	First port number in the range
 * @last:	Last port number in the range (inclusive)
 *
 * Invariant:	@last >= @first
 */
struct port_range {
	in_port_t first, last;
};

/**
 * parse_port_range() - Parse a range of port numbers '<first>[-<last>]'
 * @s:		String to parse
 * @endptr:	Update to the character after the parsed range (similar to
 *		strtol() etc.)
 * @range:	Update with the parsed values on success
 *
 * Return: -EINVAL on parsing error, -ERANGE on out of range port
 *	   numbers, 0 on success
 */
static int parse_port_range(const char *s, char **endptr,
			    struct port_range *range)
{
	unsigned long first, last;

	last = first = strtoul(s, endptr, 10);
	if (*endptr == s) /* Parsed nothing */
		return -EINVAL;
	if (**endptr == '-') { /* we have a last value too */
		const char *lasts = *endptr + 1;
		last = strtoul(lasts, endptr, 10);
		if (*endptr == lasts) /* Parsed nothing */
			return -EINVAL;
	}

	if ((last < first) || (last >= NUM_PORTS))
		return -ERANGE;

	range->first = first;
	range->last = last;

	return 0;
}

/**
 * conf_ports() - Parse port configuration options, initialise UDP/TCP sockets
 * @c:		Execution context
 * @optname:	Short option name, t, T, u, or U
 * @optarg:	Option argument (port specification)
 * @fwd:	Pointer to @port_fwd to be updated
 */
static void conf_ports(const struct ctx *c, char optname, const char *optarg,
		       struct port_fwd *fwd)
{
	char addr_buf[sizeof(struct in6_addr)] = { 0 }, *addr = addr_buf;
	char buf[BUFSIZ], *spec, *ifname = NULL, *p;
	bool exclude_only = true, bound_one = false;
	uint8_t exclude[PORT_BITMAP_SIZE] = { 0 };
	sa_family_t af = AF_UNSPEC;
	int ret;

	if (!strcmp(optarg, "none")) {
		if (fwd->mode)
			goto mode_conflict;

		fwd->mode = FWD_NONE;
		return;
	}

	if (!strcmp(optarg, "auto")) {
		if (fwd->mode)
			goto mode_conflict;

		if (c->mode != MODE_PASTA)
			die("'auto' port forwarding is only allowed for pasta");

		fwd->mode = FWD_AUTO;
		return;
	}

	if (!strcmp(optarg, "all")) {
		unsigned i;

		if (fwd->mode)
			goto mode_conflict;

		if (c->mode != MODE_PASST)
			die("'all' port forwarding is only allowed for passt");

		fwd->mode = FWD_ALL;
		memset(fwd->map, 0xff, PORT_EPHEMERAL_MIN / 8);

		for (i = 0; i < PORT_EPHEMERAL_MIN; i++) {
			if (optname == 't') {
				ret = tcp_sock_init(c, AF_UNSPEC, NULL, NULL,
						    i);
				if (ret == -ENFILE || ret == -EMFILE)
					goto enfile;
				if (!ret)
					bound_one = true;
			} else if (optname == 'u') {
				ret = udp_sock_init(c, 0, AF_UNSPEC, NULL, NULL,
						    i);
				if (ret == -ENFILE || ret == -EMFILE)
					goto enfile;
				if (!ret)
					bound_one = true;
			}
		}

		if (!bound_one)
			goto bind_fail;

		return;
	}

	if (fwd->mode > FWD_SPEC)
		die("Specific ports cannot be specified together with all/none/auto");

	fwd->mode = FWD_SPEC;

	strncpy(buf, optarg, sizeof(buf) - 1);

	if ((spec = strchr(buf, '/'))) {
		*spec = 0;
		spec++;

		if (optname != 't' && optname != 'u')
			goto bad;

		if ((ifname = strchr(buf, '%'))) {
			if (spec - ifname >= IFNAMSIZ - 1)
				goto bad;

			*ifname = 0;
			ifname++;
		}

		if (ifname == buf + 1)		/* Interface without address */
			addr = NULL;
		else if (inet_pton(AF_INET, buf, addr))
			af = AF_INET;
		else if (inet_pton(AF_INET6, buf, addr))
			af = AF_INET6;
		else
			goto bad;
	} else {
		spec = buf;

		addr = NULL;
	}

	/* Mark all exclusions first, they might be given after base ranges */
	p = spec;
	do {
		struct port_range xrange;
		unsigned i;

		if (*p != '~') {
			/* Not an exclude range, parse later */
			exclude_only = false;
			continue;
		}
		p++;

		if (parse_port_range(p, &p, &xrange))
			goto bad;
		if ((*p != '\0')  && (*p != ',')) /* Garbage after the range */
			goto bad;

		for (i = xrange.first; i <= xrange.last; i++) {
			if (bitmap_isset(exclude, i))
				goto overlap;

			bitmap_set(exclude, i);
		}
	} while ((p = next_chunk(p, ',')));

	if (exclude_only) {
		unsigned i;

		for (i = 0; i < PORT_EPHEMERAL_MIN; i++) {
			if (bitmap_isset(exclude, i))
				continue;

			bitmap_set(fwd->map, i);

			if (optname == 't') {
				ret = tcp_sock_init(c, af, addr, ifname, i);
				if (ret == -ENFILE || ret == -EMFILE)
					goto enfile;
				if (!ret)
					bound_one = true;
			} else if (optname == 'u') {
				ret = udp_sock_init(c, 0, af, addr, ifname, i);
				if (ret == -ENFILE || ret == -EMFILE)
					goto enfile;
				if (!ret)
					bound_one = true;
			} else {
				/* No way to check in advance for -T and -U */
				bound_one = true;
			}
		}

		if (!bound_one)
			goto bind_fail;

		return;
	}

	/* Now process base ranges, skipping exclusions */
	p = spec;
	do {
		struct port_range orig_range, mapped_range;
		unsigned i;

		if (*p == '~')
			/* Exclude range, already parsed */
			continue;

		if (parse_port_range(p, &p, &orig_range))
			goto bad;

		if (*p == ':') { /* There's a range to map to as well */
			if (parse_port_range(p + 1, &p, &mapped_range))
				goto bad;
			if ((mapped_range.last - mapped_range.first) !=
			    (orig_range.last - orig_range.first))
				goto bad;
		} else {
			mapped_range = orig_range;
		}

		if ((*p != '\0')  && (*p != ',')) /* Garbage after the ranges */
			goto bad;

		for (i = orig_range.first; i <= orig_range.last; i++) {
			if (bitmap_isset(fwd->map, i))
				goto overlap;

			if (bitmap_isset(exclude, i))
				continue;

			bitmap_set(fwd->map, i);

			fwd->delta[i] = mapped_range.first - orig_range.first;

			if (optname == 't') {
				ret = tcp_sock_init(c, af, addr, ifname, i);
				if (ret == -ENFILE || ret == -EMFILE)
					goto enfile;
				if (!ret)
					bound_one = true;
			} else if (optname == 'u') {
				ret = udp_sock_init(c, 0, af, addr, ifname, i);
				if (ret == -ENFILE || ret == -EMFILE)
					goto enfile;
				if (!ret)
					bound_one = true;
			} else {
				/* No way to check in advance for -T and -U */
				bound_one = true;
			}
		}
	} while ((p = next_chunk(p, ',')));

	if (!bound_one)
		goto bind_fail;

	return;
enfile:
	die("Can't open enough sockets for port specifier: %s", optarg);
bad:
	die("Invalid port specifier %s", optarg);
overlap:
	die("Overlapping port specifier %s", optarg);
mode_conflict:
	die("Port forwarding mode '%s' conflicts with previous mode", optarg);
bind_fail:
	die("Failed to bind any port for '-%c %s', exiting", optname, optarg);
}

/**
 * add_dns4() - Possibly add the IPv4 address of a DNS resolver to configuration
 * @c:		Execution context
 * @addr:	Address found in /etc/resolv.conf
 * @conf:	Pointer to reference of current entry in array of IPv4 resolvers
 */
static void add_dns4(struct ctx *c, struct in_addr *addr, struct in_addr **conf)
{
	/* Guest or container can only access local addresses via redirect */
	if (IN4_IS_ADDR_LOOPBACK(addr)) {
		if (!c->no_map_gw) {
			**conf = c->ip4.gw;
			(*conf)++;

			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_match))
				c->ip4.dns_match = c->ip4.gw;
		}
	} else {
		**conf = *addr;
		(*conf)++;
	}

	if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_host))
		c->ip4.dns_host = *addr;
}

/**
 * add_dns6() - Possibly add the IPv6 address of a DNS resolver to configuration
 * @c:		Execution context
 * @addr:	Address found in /etc/resolv.conf
 * @conf:	Pointer to reference of current entry in array of IPv6 resolvers
 */
static void add_dns6(struct ctx *c,
		     struct in6_addr *addr, struct in6_addr **conf)
{
	/* Guest or container can only access local addresses via redirect */
	if (IN6_IS_ADDR_LOOPBACK(addr)) {
		if (!c->no_map_gw) {
			memcpy(*conf, &c->ip6.gw, sizeof(**conf));
			(*conf)++;

			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_match))
				memcpy(&c->ip6.dns_match, addr, sizeof(*addr));
		}
	} else {
		memcpy(*conf, addr, sizeof(**conf));
		(*conf)++;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_host))
		c->ip6.dns_host = *addr;
}

/**
 * get_dns() - Get nameserver addresses from local /etc/resolv.conf
 * @c:		Execution context
 */
static void get_dns(struct ctx *c)
{
	struct in6_addr *dns6 = &c->ip6.dns[0], dns6_tmp;
	struct in_addr *dns4 = &c->ip4.dns[0], dns4_tmp;
	int dns4_set, dns6_set, dnss_set, dns_set, fd;
	struct fqdn *s = c->dns_search;
	struct lineread resolvconf;
	int line_len;
	char *line, *p, *end;

	dns4_set = !c->ifi4 || !IN4_IS_ADDR_UNSPECIFIED(dns4);
	dns6_set = !c->ifi6 || !IN6_IS_ADDR_UNSPECIFIED(dns6);
	dnss_set = !!*s->n || c->no_dns_search;
	dns_set = (dns4_set && dns6_set) || c->no_dns;

	if (dns_set && dnss_set)
		return;

	if ((fd = open("/etc/resolv.conf", O_RDONLY | O_CLOEXEC)) < 0)
		goto out;

	lineread_init(&resolvconf, fd);
	while ((line_len = lineread_get(&resolvconf, &line)) > 0) {
		if (!dns_set && strstr(line, "nameserver ") == line) {
			p = strrchr(line, ' ');
			if (!p)
				continue;

			end = strpbrk(line, "%\n");
			if (end)
				*end = 0;

			if (!dns4_set &&
			    dns4 - &c->ip4.dns[0] < ARRAY_SIZE(c->ip4.dns) - 1
			    && inet_pton(AF_INET, p + 1, &dns4_tmp))
				add_dns4(c, &dns4_tmp, &dns4);

			if (!dns6_set &&
			    dns6 - &c->ip6.dns[0] < ARRAY_SIZE(c->ip6.dns) - 1
			    && inet_pton(AF_INET6, p + 1, &dns6_tmp))
				add_dns6(c, &dns6_tmp, &dns6);
		} else if (!dnss_set && strstr(line, "search ") == line &&
			   s == c->dns_search) {
			end = strpbrk(line, "\n");
			if (end)
				*end = 0;

			/* cppcheck-suppress strtokCalled */
			if (!strtok(line, " \t"))
				continue;

			while (s - c->dns_search < ARRAY_SIZE(c->dns_search) - 1
			       /* cppcheck-suppress strtokCalled */
			       && (p = strtok(NULL, " \t"))) {
				strncpy(s->n, p, sizeof(c->dns_search[0]));
				s++;
				*s->n = 0;
			}
		}
	}

	if (line_len < 0)
		warn("Error reading /etc/resolv.conf: %s", strerror(errno));
	close(fd);

out:
	if (!dns_set && dns4 == c->ip4.dns && dns6 == c->ip6.dns)
		warn("Couldn't get any nameserver address");
}

/**
 * conf_netns_opt() - Parse --netns option
 * @netns:	buffer of size PATH_MAX, updated with netns path
 * @arg:	--netns argument
 */
static void conf_netns_opt(char *netns, const char *arg)
{
	int ret;

	if (!strchr(arg, '/')) {
		/* looks like a netns name */
		ret = snprintf(netns, PATH_MAX, "%s/%s", NETNS_RUN_DIR, arg);
	} else {
		/* otherwise assume it's a netns path */
		ret = snprintf(netns, PATH_MAX, "%s", arg);
	}

	if (ret <= 0 || ret > PATH_MAX)
		die("Network namespace name/path %s too long");
}

/**
 * conf_pasta_ns() - Validate all pasta namespace options
 * @netns_only:	Don't use userns, may be updated
 * @userns:	buffer of size PATH_MAX, initially contains --userns
 *		argument (may be empty), updated with userns path
 * @netns:	buffer of size PATH_MAX, initial contains --netns
 *		argument (may be empty), updated with netns path
 * @optind:	Index of first non-option argument
 * @argc:	Number of arguments
 * @argv:	Command line arguments
 */
static void conf_pasta_ns(int *netns_only, char *userns, char *netns,
			  int optind, int argc, char *argv[])
{
	if (*netns_only && *userns)
		die("Both --userns and --netns-only given");

	if (*netns && optind != argc)
		die("Both --netns and PID or command given");

	if (optind + 1 == argc) {
		char *endptr;
		long pidval;

		pidval = strtol(argv[optind], &endptr, 10);
		if (!*endptr) {
			/* Looks like a pid */
			if (pidval < 0 || pidval > INT_MAX)
				die("Invalid PID %s", argv[optind]);

			snprintf(netns, PATH_MAX, "/proc/%ld/ns/net", pidval);
			if (!*userns)
				snprintf(userns, PATH_MAX, "/proc/%ld/ns/user",
					 pidval);
		}
	}

	/* Attaching to a netns/PID, with no userns given */
	if (*netns && !*userns)
		*netns_only = 1;
}

/** conf_ip4_prefix() - Parse an IPv4 prefix length or netmask
 * @arg:	Netmask in dotted decimal or prefix length
 *
 * Return: Validated prefix length on success, -1 on failure
 */
static int conf_ip4_prefix(const char *arg)
{
	struct in_addr mask;
	unsigned long len;

	if (inet_pton(AF_INET, arg, &mask)) {
		in_addr_t hmask = ntohl(mask.s_addr);
		len = __builtin_popcount(hmask);
		if ((hmask << len) != 0)
			return -1;
	} else {
		errno = 0;
		len = strtoul(optarg, NULL, 0);
		if (len > 32 || errno)
			return -1;
	}

	return len;
}

/**
 * conf_ip4() - Verify or detect IPv4 support, get relevant addresses
 * @ifi:	Host interface to attempt (0 to determine one)
 * @ip4:	IPv4 context (will be written)
 * @mac:	MAC address to use (written if unset)
 *
 * Return:	Interface index for IPv4, or 0 on failure.
 */
static unsigned int conf_ip4(unsigned int ifi,
			     struct ip4_ctx *ip4, unsigned char *mac)
{
	in_addr_t addr, gw;
	int shift;

	if (!ifi)
		ifi = nl_get_ext_if(AF_INET);

	if (!ifi) {
		warn("No external routable interface for IPv4");
		return 0;
	}

	if (IN4_IS_ADDR_UNSPECIFIED(&ip4->gw))
		nl_route(0, ifi, AF_INET, &ip4->gw);

	if (IN4_IS_ADDR_UNSPECIFIED(&ip4->addr))
		nl_addr(0, ifi, AF_INET, &ip4->addr, &ip4->prefix_len, NULL);

	addr = ntohl(ip4->addr.s_addr);
	gw = ntohl(ip4->gw.s_addr);

	if (!ip4->prefix_len) {
		if (IN_CLASSA(addr))
			ip4->prefix_len = (32 - IN_CLASSA_NSHIFT);
		else if (IN_CLASSB(addr))
			ip4->prefix_len = (32 - IN_CLASSB_NSHIFT);
		else if (IN_CLASSC(addr))
			ip4->prefix_len = (32 - IN_CLASSC_NSHIFT);
		else
			ip4->prefix_len = 32;
	}

	/* We might get an address with a netmask that makes the default
	 * gateway unreachable, and in that case we would fail to configure
	 * the default route, with --config-net, or presumably a DHCP client
	 * in the guest or container would face the same issue.
	 *
	 * The host might have another route, to the default gateway itself,
	 * fixing the situation, but we only read default routes.
	 *
	 * Fix up the mask to allow reaching the default gateway from our
	 * configured address, if needed, and only if we find a non-zero
	 * mask that makes the gateway reachable.
	 */
	shift = 32 - ip4->prefix_len;
	while (shift < 32 && addr >> shift != gw >> shift)
		shift++;
	if (shift < 32)
		ip4->prefix_len = 32 - shift;

	memcpy(&ip4->addr_seen, &ip4->addr, sizeof(ip4->addr_seen));

	if (MAC_IS_ZERO(mac))
		nl_link(0, ifi, mac, 0, 0);

	if (IN4_IS_ADDR_UNSPECIFIED(&ip4->gw) ||
	    IN4_IS_ADDR_UNSPECIFIED(&ip4->addr) ||
	    MAC_IS_ZERO(mac))
		return 0;

	return ifi;
}

/**
 * conf_ip6() - Verify or detect IPv6 support, get relevant addresses
 * @ifi:	Host interface to attempt (0 to determine one)
 * @ip6:	IPv6 context (will be written)
 * @mac:	MAC address to use (written if unset)
 *
 * Return:	Interface index for IPv6, or 0 on failure.
 */
static unsigned int conf_ip6(unsigned int ifi,
			     struct ip6_ctx *ip6, unsigned char *mac)
{
	int prefix_len = 0;

	if (!ifi)
		ifi = nl_get_ext_if(AF_INET6);

	if (!ifi) {
		warn("No external routable interface for IPv6");
		return 0;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->gw))
		nl_route(0, ifi, AF_INET6, &ip6->gw);

	nl_addr(0, ifi, AF_INET6,
		IN6_IS_ADDR_UNSPECIFIED(&ip6->addr) ? &ip6->addr : NULL,
		&prefix_len, &ip6->addr_ll);

	memcpy(&ip6->addr_seen, &ip6->addr, sizeof(ip6->addr));
	memcpy(&ip6->addr_ll_seen, &ip6->addr_ll, sizeof(ip6->addr_ll));

	if (MAC_IS_ZERO(mac))
		nl_link(0, ifi, mac, 0, 0);

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->gw) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->addr) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->addr_ll) ||
	    MAC_IS_ZERO(mac))
		return 0;

	return ifi;
}

/**
 * usage() - Print usage and exit
 * @name:	Executable name
 */
static void usage(const char *name)
{
	if (strstr(name, "pasta")) {
		info("Usage: %s [OPTION]... [COMMAND] [ARGS]...", name);
		info("       %s [OPTION]... PID", name);
		info("       %s [OPTION]... --netns [PATH|NAME]", name);
		info("");
		info("Without PID or --netns, run the given command or a");
		info("default shell in a new network and user namespace, and");
		info("connect it via pasta.");
	} else {
		info("Usage: %s [OPTION]...", name);
	}
	info("");


	info(   "  -d, --debug		Be verbose");
	info(   "      --trace		Be extra verbose, implies --debug");
	info(   "  -q, --quiet		Don't print informational messages");
	info(   "  -f, --foreground	Don't run in background");
	info(   "    default: run in background if started from a TTY");
	info(   "  -e, --stderr		Log to stderr too");
	info(   "    default: log to system logger only if started from a TTY");
	info(   "  -l, --log-file PATH	Log (only) to given file");
	info(   "  --log-size BYTES	Maximum size of log file");
	info(   "    default: 1 MiB");
	info(   "  --runas UID|UID:GID 	Run as given UID, GID, which can be");
	info(   "    numeric, or login and group names");
	info(   "    default: drop to user \"nobody\"");
	info(   "  -h, --help		Display this help message and exit");
	info(   "  --version		Show version and exit");

	if (strstr(name, "pasta")) {
		info(   "  -I, --ns-ifname NAME	namespace interface name");
		info(   "    default: same interface name as external one");
	} else {
		info(   "  -s, --socket PATH	UNIX domain socket path");
		info(   "    default: probe free path starting from "
		     UNIX_SOCK_PATH, 1);
	}

	info(   "  -F, --fd FD		Use FD as pre-opened connected socket");
	info(   "  -p, --pcap FILE	Log tap-facing traffic to pcap file");
	info(   "  -P, --pid FILE	Write own PID to the given file");
	info(   "  -m, --mtu MTU	Assign MTU via DHCP/NDP");
	info(   "    a zero value disables assignment");
	info(   "    default: 65520: maximum 802.3 MTU minus 802.3 header");
	info(   "                    length, rounded to 32 bits (IPv4 words)");
	info(   "  -a, --address ADDR	Assign IPv4 or IPv6 address ADDR");
	info(   "    can be specified zero to two times (for IPv4 and IPv6)");
	info(   "    default: use addresses from interface with default route");
	info(   "  -n, --netmask MASK	Assign IPv4 MASK, dot-decimal or bits");
	info(   "    default: netmask from matching address on the host");
	info(   "  -M, --mac-addr ADDR	Use source MAC address ADDR");
	info(   "    default: MAC address from interface with default route");
	info(   "  -g, --gateway ADDR	Pass IPv4 or IPv6 address as gateway");
	info(   "    default: gateway from interface with default route");
	info(   "  -i, --interface NAME	Interface for addresses and routes");
	info(   "    default: from --outbound-if4 and --outbound-if6, if any");
	info(   "             otherwise interface with first default route");
	info(   "  -o, --outbound ADDR	Bind to address as outbound source");
	info(   "    can be specified zero to two times (for IPv4 and IPv6)");
	info(   "    default: use source address from routing tables");
	info(   "  --outbound-if4 NAME	Bind to outbound interface for IPv4");
	info(   "    default: use interface from default route");
	info(   "  --outbound-if6 NAME	Bind to outbound interface for IPv6");
	info(   "    default: use interface from default route");
	info(   "  -D, --dns ADDR	Use IPv4 or IPv6 address as DNS");
	info(   "    can be specified multiple times");
	info(   "    a single, empty option disables DNS information");
	if (strstr(name, "pasta"))
		info(   "    default: don't use any addresses");
	else
		info(   "    default: use addresses from /etc/resolv.conf");

	info(   "  -S, --search LIST	Space-separated list, search domains");
	info(   "    a single, empty option disables the DNS search list");
	if (strstr(name, "pasta"))
		info(   "    default: don't use any search list");
	else
		info(   "    default: use search list from /etc/resolv.conf");

	if (strstr(name, "pasta"))
		info("  --dhcp-dns	\tPass DNS list via DHCP/DHCPv6/NDP");
	else
		info("  --no-dhcp-dns	No DNS list in DHCP/DHCPv6/NDP");

	if (strstr(name, "pasta"))
		info("  --dhcp-search	Pass list via DHCP/DHCPv6/NDP");
	else
		info("  --no-dhcp-search	No list in DHCP/DHCPv6/NDP");

	info(   "  --dns-forward ADDR	Forward DNS queries sent to ADDR");
	info(   "    can be specified zero to two times (for IPv4 and IPv6)");
	info(   "    default: don't forward DNS queries");

	info(   "  --no-tcp		Disable TCP protocol handler");
	info(   "  --no-udp		Disable UDP protocol handler");
	info(   "  --no-icmp		Disable ICMP/ICMPv6 protocol handler");
	info(   "  --no-dhcp		Disable DHCP server");
	info(   "  --no-ndp		Disable NDP responses");
	info(   "  --no-dhcpv6		Disable DHCPv6 server");
	info(   "  --no-ra		Disable router advertisements");
	info(   "  --no-map-gw		Don't map gateway address to host");
	info(   "  -4, --ipv4-only	Enable IPv4 operation only");
	info(   "  -6, --ipv6-only	Enable IPv6 operation only");

	info(   "  --dns-redirect ADDR	Redirect DNS queries sent to ADDR");
	info(   "    can be specified zero to two times (for IPv4 and IPv6)");
	info(   "    default: don't redirect DNS queries");

	if (strstr(name, "pasta"))
		goto pasta_opts;

	info(   "  -1, --one-off	Quit after handling one single client");
	info(   "  -t, --tcp-ports SPEC	TCP port forwarding to guest");
	info(   "    can be specified multiple times");
	info(   "    SPEC can be:");
	info(   "      'none': don't forward any ports");
	info(   "      'all': forward all unbound, non-ephemeral ports");
	info(   "      a comma-separated list, optionally ranged with '-'");
	info(   "        and optional target ports after ':', with optional");
	info(   "        address specification suffixed by '/' and optional");
	info(   "        interface prefixed by '%%'. Ranges can be reduced by");
	info(   "        excluding ports or ranges prefixed by '~'");
	info(   "        Examples:");
	info(   "        -t 22		Forward local port 22 to 22 on guest");
	info(   "        -t 22:23	Forward local port 22 to 23 on guest");
	info(   "        -t 22,25	Forward ports 22, 25 to ports 22, 25");
	info(   "        -t 22-80  	Forward ports 22 to 80");
	info(   "        -t 22-80:32-90	Forward ports 22 to 80 to");
	info(   "			corresponding port numbers plus 10");
	info(   "        -t 192.0.2.1/5	Bind port 5 of 192.0.2.1 to guest");
	info(   "        -t 5-25,~10-20	Forward ports 5 to 9, and 21 to 25");
	info(   "        -t ~25		Forward all ports except for 25");
	info(   "    default: none");
	info(   "  -u, --udp-ports SPEC	UDP port forwarding to guest");
	info(   "    SPEC is as described for TCP above");
	info(   "    default: none");

	exit(EXIT_FAILURE);

pasta_opts:

	info(   "  -t, --tcp-ports SPEC	TCP port forwarding to namespace");
	info(   "    can be specified multiple times");
	info(   "    SPEC can be:");
	info(   "      'none': don't forward any ports");
	info(   "      'auto': forward all ports currently bound in namespace");
	info(   "      a comma-separated list, optionally ranged with '-'");
	info(   "        and optional target ports after ':', with optional");
	info(   "        address specification suffixed by '/' and optional");
	info(   "        interface prefixed by '%%'. Examples:");
	info(   "        -t 22	Forward local port 22 to port 22 in netns");
	info(   "        -t 22:23	Forward local port 22 to port 23");
	info(   "        -t 22,25	Forward ports 22, 25 to ports 22, 25");
	info(   "        -t 22-80	Forward ports 22 to 80");
	info(   "        -t 22-80:32-90	Forward ports 22 to 80 to");
	info(   "			corresponding port numbers plus 10");
	info(   "        -t 192.0.2.1/5	Bind port 5 of 192.0.2.1 to namespace");
	info(   "        -t 5-25,~10-20	Forward ports 5 to 9, and 21 to 25");
	info(   "        -t ~25		Forward all bound ports except for 25");
	info(   "    default: auto");
	info(   "    IPv6 bound ports are also forwarded for IPv4");
	info(   "  -u, --udp-ports SPEC	UDP port forwarding to namespace");
	info(   "    SPEC is as described for TCP above");
	info(   "    default: auto");
	info(   "    IPv6 bound ports are also forwarded for IPv4");
	info(   "    unless specified, with '-t auto', UDP ports with numbers");
	info(   "    corresponding to forwarded TCP port numbers are");
	info(   "    forwarded too");
	info(   "  -T, --tcp-ns SPEC	TCP port forwarding to init namespace");
	info(   "    SPEC is as described above");
	info(   "    default: auto");
	info(   "  -U, --udp-ns SPEC	UDP port forwarding to init namespace");
	info(   "    SPEC is as described above");
	info(   "    default: auto");
	info(   "  --userns NSPATH 	Target user namespace to join");
	info(   "  --netns PATH|NAME	Target network namespace to join");
	info(   "  --netns-only		Don't join existing user namespace");
	info(   "    implied if PATH or NAME are given without --userns");
	info(   "  --no-netns-quit	Don't quit if filesystem-bound target");
	info(   "  			network namespace is deleted");
	info(   "  --config-net		Configure tap interface in namespace");
	info(   "  --ns-mac-addr ADDR	Set MAC address on tap interface");

	exit(EXIT_FAILURE);
}

/**
 * conf_print() - Print fundamental configuration parameters
 * @c:		Execution context
 */
static void conf_print(const struct ctx *c)
{
	char buf4[INET_ADDRSTRLEN], buf6[INET6_ADDRSTRLEN], ifn[IFNAMSIZ];
	int i;

	info("Template interface: %s%s%s%s%s",
	     c->ifi4 ? if_indextoname(c->ifi4, ifn) : "",
	     c->ifi4 ? " (IPv4)" : "",
	     (c->ifi4 && c->ifi6) ? ", " : "",
	     c->ifi6 ? if_indextoname(c->ifi6, ifn) : "",
	     c->ifi6 ? " (IPv6)" : "");

	if (*c->ip4.ifname_out || *c->ip6.ifname_out) {
		info("Outbound interface: %s%s%s%s%s",
		     *c->ip4.ifname_out ? c->ip4.ifname_out : "",
		     *c->ip4.ifname_out ? " (IPv4)" : "",
		     (*c->ip4.ifname_out && *c->ip6.ifname_out) ? ", " : "",
		     *c->ip6.ifname_out ? c->ip6.ifname_out : "",
		     *c->ip6.ifname_out ? " (IPv6)" : "");
	}

	if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out) ||
	    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)) {
		info("Outbound address: %s%s%s",
		     IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out) ? "" :
		     inet_ntop(AF_INET, &c->ip4.addr_out, buf4, sizeof(buf4)),
		     (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out) &&
		      !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)) ? ", " : "",
		     IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out) ? "" :
		     inet_ntop(AF_INET6, &c->ip6.addr_out, buf6, sizeof(buf6)));
	}

	if (c->mode == MODE_PASTA)
		info("Namespace interface: %s", c->pasta_ifn);

	info("MAC:");
	info("    host: %02x:%02x:%02x:%02x:%02x:%02x",
	     c->mac[0], c->mac[1], c->mac[2],
	     c->mac[3], c->mac[4], c->mac[5]);

	if (c->ifi4) {
		if (!c->no_dhcp) {
			uint32_t mask;

			mask = htonl(0xffffffff << (32 - c->ip4.prefix_len));

			info("DHCP:");
			info("    assign: %s",
			     inet_ntop(AF_INET, &c->ip4.addr, buf4, sizeof(buf4)));
			info("    mask: %s",
			     inet_ntop(AF_INET, &mask,        buf4, sizeof(buf4)));
			info("    router: %s",
			     inet_ntop(AF_INET, &c->ip4.gw,   buf4, sizeof(buf4)));
		}

		for (i = 0; !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns[i]); i++) {
			if (!i)
				info("DNS:");
			inet_ntop(AF_INET, &c->ip4.dns[i], buf4, sizeof(buf4));
			info("    %s", buf4);
		}

		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("DNS search list:");
			info("    %s", c->dns_search[i].n);
		}
	}

	if (c->ifi6) {
		if (!c->no_ndp && !c->no_dhcpv6)
			info("NDP/DHCPv6:");
		else if (!c->no_ndp)
			info("DHCPv6:");
		else if (!c->no_dhcpv6)
			info("NDP:");
		else
			goto dns6;

		info("    assign: %s",
		     inet_ntop(AF_INET6, &c->ip6.addr, buf6, sizeof(buf6)));
		info("    router: %s",
		     inet_ntop(AF_INET6, &c->ip6.gw,   buf6, sizeof(buf6)));
		info("    our link-local: %s",
		     inet_ntop(AF_INET6, &c->ip6.addr_ll, buf6, sizeof(buf6)));

dns6:
		for (i = 0; !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns[i]); i++) {
			if (!i)
				info("DNS:");
			inet_ntop(AF_INET6, &c->ip6.dns[i], buf6, sizeof(buf6));
			info("    %s", buf6);
		}

		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("DNS search list:");
			info("    %s", c->dns_search[i].n);
		}
	}
}

/**
 * conf_runas() - Handle --runas: look up desired UID and GID
 * @opt:	Passed option value
 * @uid:	User ID, set on return if valid
 * @gid:	Group ID, set on return if valid
 *
 * Return: 0 on success, negative error code on failure
 */
static int conf_runas(char *opt, unsigned int *uid, unsigned int *gid)
{
	const char *uopt, *gopt = NULL;
	char *sep = strchr(opt, ':');
	char *endptr;

	if (sep) {
		*sep = '\0';
		gopt = sep + 1;
	}
	uopt = opt;

	*gid = *uid = strtol(uopt, &endptr, 0);
	if (*endptr) {
#ifndef GLIBC_NO_STATIC_NSS
		/* Not numeric, look up as a username */
		struct passwd *pw;
		/* cppcheck-suppress getpwnamCalled */
		if (!(pw = getpwnam(uopt)) || !(*uid = pw->pw_uid))
			return -ENOENT;
		*gid = pw->pw_gid;
#else
		return -EINVAL;
#endif
	}

	if (!gopt)
		return 0;

	*gid = strtol(gopt, &endptr, 0);
	if (*endptr) {
#ifndef GLIBC_NO_STATIC_NSS
		/* Not numeric, look up as a group name */
		struct group *gr;
		/* cppcheck-suppress getgrnamCalled */
		if (!(gr = getgrnam(gopt)))
			return -ENOENT;
		*gid = gr->gr_gid;
#else
		return -EINVAL;
#endif
	}

	return 0;
}

/**
 * conf_ugid() - Determine UID and GID to run as
 * @runas:	--runas option, may be NULL
 * @uid:	User ID, set on success
 * @gid:	Group ID, set on success
 */
static void conf_ugid(char *runas, uid_t *uid, gid_t *gid)
{
	const char root_uid_map[] = "         0          0 4294967295";
	char buf[BUFSIZ];
	int fd;

	/* If user has specified --runas, that takes precedence... */
	if (runas) {
		if (conf_runas(runas, uid, gid))
			die("Invalid --runas option: %s", runas);
		return;
	}

	/* ...otherwise default to current user and group... */
	*uid = geteuid();
	*gid = getegid();

	/* ...as long as it's not root... */
	if (*uid)
		return;

	/* ...or at least not root in the init namespace... */
	if ((fd = open("/proc/self/uid_map", O_RDONLY | O_CLOEXEC)) < 0) {
		die("Can't determine if we're in init namespace: %s",
		    strerror(errno));
	}

	if (read(fd, buf, BUFSIZ) != sizeof(root_uid_map) ||
	    strncmp(buf, root_uid_map, sizeof(root_uid_map) - 1)) {
		close(fd);
		return;
	}

	close(fd);

	/* ...otherwise use nobody:nobody */
	warn("Don't run as root. Changing to nobody...");
	{
#ifndef GLIBC_NO_STATIC_NSS
		struct passwd *pw;
		/* cppcheck-suppress getpwnamCalled */
		pw = getpwnam("nobody");
		if (!pw) {
			perror("getpwnam");
			exit(EXIT_FAILURE);
		}

		*uid = pw->pw_uid;
		*gid = pw->pw_gid;
#else
		/* Common value for 'nobody', not really specified */
		*uid = *gid = 65534;
#endif
	}
}

/**
 * conf() - Process command-line arguments and set configuration
 * @c:		Execution context
 * @argc:	Argument count
 * @argv:	Options, plus target PID for pasta mode
 */
void conf(struct ctx *c, int argc, char **argv)
{
	int netns_only = 0;
	struct option options[] = {
		{"debug",	no_argument,		NULL,		'd' },
		{"quiet",	no_argument,		NULL,		'q' },
		{"foreground",	no_argument,		NULL,		'f' },
		{"stderr",	no_argument,		NULL,		'e' },
		{"log-file",	required_argument,	NULL,		'l' },
		{"help",	no_argument,		NULL,		'h' },
		{"socket",	required_argument,	NULL,		's' },
		{"fd",		required_argument,	NULL,		'F' },
		{"ns-ifname",	required_argument,	NULL,		'I' },
		{"pcap",	required_argument,	NULL,		'p' },
		{"pid",		required_argument,	NULL,		'P' },
		{"mtu",		required_argument,	NULL,		'm' },
		{"address",	required_argument,	NULL,		'a' },
		{"netmask",	required_argument,	NULL,		'n' },
		{"mac-addr",	required_argument,	NULL,		'M' },
		{"gateway",	required_argument,	NULL,		'g' },
		{"interface",	required_argument,	NULL,		'i' },
		{"outbound",	required_argument,	NULL,		'o' },
		{"dns",		required_argument,	NULL,		'D' },
		{"search",	required_argument,	NULL,		'S' },
		{"no-tcp",	no_argument,		&c->no_tcp,	1 },
		{"no-udp",	no_argument,		&c->no_udp,	1 },
		{"no-icmp",	no_argument,		&c->no_icmp,	1 },
		{"no-dhcp",	no_argument,		&c->no_dhcp,	1 },
		{"no-dhcpv6",	no_argument,		&c->no_dhcpv6,	1 },
		{"no-ndp",	no_argument,		&c->no_ndp,	1 },
		{"no-ra",	no_argument,		&c->no_ra,	1 },
		{"no-map-gw",	no_argument,		&c->no_map_gw,	1 },
		{"ipv4-only",	no_argument,		NULL,		'4' },
		{"ipv6-only",	no_argument,		NULL,		'6' },
		{"one-off",	no_argument,		NULL,		'1' },
		{"tcp-ports",	required_argument,	NULL,		't' },
		{"udp-ports",	required_argument,	NULL,		'u' },
		{"tcp-ns",	required_argument,	NULL,		'T' },
		{"udp-ns",	required_argument,	NULL,		'U' },
		{"userns",	required_argument,	NULL,		2 },
		{"netns",	required_argument,	NULL,		3 },
		{"netns-only",	no_argument,		&netns_only,	1 },
		{"config-net",	no_argument,		&c->pasta_conf_ns, 1 },
		{"ns-mac-addr",	required_argument,	NULL,		4 },
		{"dhcp-dns",	no_argument,		NULL,		5 },
		{"no-dhcp-dns",	no_argument,		NULL,		6 },
		{"dhcp-search", no_argument,		NULL,		7 },
		{"no-dhcp-search", no_argument,		NULL,		8 },
		{"dns-forward",	required_argument,	NULL,		9 },
		{"no-netns-quit", no_argument,		NULL,		10 },
		{"trace",	no_argument,		NULL,		11 },
		{"runas",	required_argument,	NULL,		12 },
		{"log-size",	required_argument,	NULL,		13 },
		{"version",	no_argument,		NULL,		14 },
		{"outbound-if4", required_argument,	NULL,		15 },
		{"outbound-if6", required_argument,	NULL,		16 },
		{"dns-redirect", required_argument,	NULL,		17 },
		{ 0 },
	};
	struct get_bound_ports_ns_arg ns_ports_arg = { .c = c };
	char userns[PATH_MAX] = { 0 }, netns[PATH_MAX] = { 0 };
	bool v4_only = false, v6_only = false;
	char *runas = NULL, *logfile = NULL;
	struct in6_addr *dns6 = c->ip6.dns;
	struct fqdn *dnss = c->dns_search;
	struct in_addr *dns4 = c->ip4.dns;
	unsigned int ifi4 = 0, ifi6 = 0;
	const char *optstring;
	int name, ret, b, i;
	size_t logsize = 0;
	uid_t uid;
	gid_t gid;

	if (c->mode == MODE_PASTA) {
		c->no_dhcp_dns = c->no_dhcp_dns_search = 1;
		optstring = "dqfel:hF:I:p:P:m:a:n:M:g:i:o:D:S:46t:u:T:U:";
	} else {
		optstring = "dqfel:hs:F:p:P:m:a:n:M:g:i:o:D:S:461t:u:";
	}

	c->tcp.fwd_in.mode = c->tcp.fwd_out.mode = 0;
	c->udp.fwd_in.f.mode = c->udp.fwd_out.f.mode = 0;

	do {
		name = getopt_long(argc, argv, optstring, options, NULL);

		switch (name) {
		case -1:
		case 0:
			break;
		case 2:
			if (c->mode != MODE_PASTA)
				die("--userns is for pasta mode only");

			ret = snprintf(userns, sizeof(userns), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(userns))
				die("Invalid userns: %s", optarg);

			break;
		case 3:
			if (c->mode != MODE_PASTA)
				die("--netns is for pasta mode only");

			conf_netns_opt(netns, optarg);
			break;
		case 4:
			if (c->mode != MODE_PASTA)
				die("--ns-mac-addr is for pasta mode only");

			for (i = 0; i < ETH_ALEN; i++) {
				errno = 0;
				b = strtol(optarg + (intptr_t)i * 3, NULL, 16);
				if (b < 0 || b > UCHAR_MAX || errno)
					die("Invalid MAC address: %s", optarg);

				c->mac_guest[i] = b;
			}
			break;
		case 5:
			if (c->mode != MODE_PASTA)
				die("--dhcp-dns is for pasta mode only");

			c->no_dhcp_dns = 0;
			break;
		case 6:
			if (c->mode != MODE_PASST)
				die("--no-dhcp-dns is for passt mode only");

			c->no_dhcp_dns = 1;
			break;
		case 7:
			if (c->mode != MODE_PASTA)
				die("--dhcp-search is for pasta mode only");

			c->no_dhcp_dns_search = 0;
			break;
		case 8:
			if (c->mode != MODE_PASST)
				die("--no-dhcp-search is for passt mode only");

			c->no_dhcp_dns_search = 1;
			break;
		case 9:
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_match)     &&
			    inet_pton(AF_INET6, optarg, &c->ip6.dns_match) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_match)    &&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.dns_match))
				break;

			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_match)    &&
			    inet_pton(AF_INET, optarg, &c->ip4.dns_match) &&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_match)   &&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.dns_match)     &&
			    !IN4_IS_ADDR_LOOPBACK(&c->ip4.dns_match))
				break;

			die("Invalid DNS forwarding address: %s", optarg);
			break;
		case 10:
			if (c->mode != MODE_PASTA)
				die("--no-netns-quit is for pasta mode only");

			c->no_netns_quit = 1;
			break;
		case 11:
			if (c->trace)
				die("Multiple --trace options given");

			if (c->quiet)
				die("Either --trace or --quiet");

			c->trace = c->debug = 1;
			break;
		case 12:
			if (runas)
				die("Multiple --runas options given");

			runas = optarg;
			break;
		case 13:
			if (logsize)
				die("Multiple --log-size options given");

			errno = 0;
			logsize = strtol(optarg, NULL, 0);

			if (logsize < LOGFILE_SIZE_MIN || errno)
				die("Invalid --log-size: %s", optarg);

			break;
		case 14:
			fprintf(stdout,
				c->mode == MODE_PASST ? "passt " : "pasta ");
			fprintf(stdout, VERSION_BLOB);
			exit(EXIT_SUCCESS);
		case 15:
			if (*c->ip4.ifname_out)
				die("Redundant outbound interface: %s", optarg);

			ret = snprintf(c->ip4.ifname_out,
				       sizeof(c->ip4.ifname_out), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->ip4.ifname_out))
				die("Invalid interface name: %s", optarg);

			break;
		case 16:
			if (*c->ip6.ifname_out)
				die("Redundant outbound interface: %s", optarg);

			ret = snprintf(c->ip6.ifname_out,
				       sizeof(c->ip6.ifname_out), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->ip6.ifname_out))
				die("Invalid interface name: %s", optarg);

			break;
		case 17:
			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_redirect)    &&
			    inet_pton(AF_INET, optarg, &c->ip4.dns_redirect) &&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_redirect)   &&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.dns_redirect))
				break;

			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_redirect)     &&
			    inet_pton(AF_INET6, optarg, &c->ip6.dns_redirect) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_match))
				break;

			die("Invalid DNS redirect address: %s", optarg);
			break;
		case 'd':
			if (c->debug)
				die("Multiple --debug options given");

			if (c->quiet)
				die("Either --debug or --quiet");

			c->debug = 1;
			break;
		case 'e':
			if (logfile)
				die("Can't log to both file and stderr");

			if (c->force_stderr)
				die("Multiple --stderr options given");

			c->force_stderr = 1;
			break;
		case 'l':
			if (c->force_stderr)
				die("Can't log to both stderr and file");

			if (logfile)
				die("Multiple --log-file options given");

			logfile = optarg;
			break;
		case 'q':
			if (c->quiet)
				die("Multiple --quiet options given");

			if (c->debug)
				die("Either --debug or --quiet");

			c->quiet = 1;
			break;
		case 'f':
			if (c->foreground)
				die("Multiple --foreground options given");

			c->foreground = 1;
			break;
		case 's':
			if (*c->sock_path)
				die("Multiple --socket options given");

			ret = snprintf(c->sock_path, UNIX_SOCK_MAX - 1, "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->sock_path))
				die("Invalid socket path: %s", optarg);

			break;
		case 'F':
			if (c->fd_tap >= 0)
				die("Multiple --fd options given");

			errno = 0;
			c->fd_tap = strtol(optarg, NULL, 0);

			if (c->fd_tap < 0 || errno)
				die("Invalid --fd: %s", optarg);

			c->one_off = true;

			break;
		case 'I':
			if (*c->pasta_ifn)
				die("Multiple --ns-ifname options given");

			ret = snprintf(c->pasta_ifn, IFNAMSIZ - 1, "%s",
				       optarg);
			if (ret <= 0 || ret >= IFNAMSIZ - 1)
				die("Invalid interface name: %s", optarg);

			break;
		case 'p':
			if (*c->pcap)
				die("Multiple --pcap options given");

			ret = snprintf(c->pcap, sizeof(c->pcap), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pcap))
				die("Invalid pcap path: %s", optarg);

			break;
		case 'P':
			if (*c->pid_file)
				die("Multiple --pid options given");

			ret = snprintf(c->pid_file, sizeof(c->pid_file), "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pid_file))
				die("Invalid PID file: %s", optarg);

			break;
		case 'm':
			if (c->mtu)
				die("Multiple --mtu options given");

			errno = 0;
			c->mtu = strtol(optarg, NULL, 0);

			if (!c->mtu) {
				c->mtu = -1;
				break;
			}

			if (c->mtu < ETH_MIN_MTU || c->mtu > (int)ETH_MAX_MTU ||
			    errno)
				die("Invalid MTU: %s", optarg);

			break;
		case 'a':
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr)	&&
			    inet_pton(AF_INET6, optarg, &c->ip6.addr)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr)	&&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.addr)		&&
			    !IN6_IS_ADDR_V4MAPPED(&c->ip6.addr)		&&
			    !IN6_IS_ADDR_V4COMPAT(&c->ip6.addr)		&&
			    !IN6_IS_ADDR_MULTICAST(&c->ip6.addr))
				break;

			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr)	&&
			    inet_pton(AF_INET, optarg, &c->ip4.addr)	&&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr)	&&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.addr)	&&
			    !IN4_IS_ADDR_LOOPBACK(&c->ip4.addr)		&&
			    !IN4_IS_ADDR_MULTICAST(&c->ip4.addr))
				break;

			die("Invalid address: %s", optarg);
			break;
		case 'n':
			c->ip4.prefix_len = conf_ip4_prefix(optarg);
			if (c->ip4.prefix_len < 0)
				die("Invalid netmask: %s", optarg);

			break;
		case 'M':
			for (i = 0; i < ETH_ALEN; i++) {
				errno = 0;
				b = strtol(optarg + (intptr_t)i * 3, NULL, 16);
				if (b < 0 || b > UCHAR_MAX || errno)
					die("Invalid MAC address: %s", optarg);

				c->mac[i] = b;
			}
			break;
		case 'g':
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.gw)		&&
			    inet_pton(AF_INET6, optarg, &c->ip6.gw)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.gw)	&&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.gw))
				break;

			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.gw)		&&
			    inet_pton(AF_INET, optarg, &c->ip4.gw)	&&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.gw)	&&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.gw)		&&
			    !IN4_IS_ADDR_LOOPBACK(&c->ip4.gw))
				break;

			die("Invalid gateway address: %s", optarg);
			break;
		case 'i':
			if (ifi4 || ifi6)
				die("Redundant interface: %s", optarg);

			if (!(ifi4 = ifi6 = if_nametoindex(optarg)))
				die("Invalid interface name %s: %s", optarg,
				    strerror(errno));
			break;
		case 'o':
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)	  &&
			    inet_pton(AF_INET6, optarg, &c->ip6.addr_out) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)	  &&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.addr_out)	  &&
			    !IN6_IS_ADDR_V4MAPPED(&c->ip6.addr_out)	  &&
			    !IN6_IS_ADDR_V4COMPAT(&c->ip6.addr_out)	  &&
			    !IN6_IS_ADDR_MULTICAST(&c->ip6.addr_out))
				break;

			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out)	 &&
			    inet_pton(AF_INET, optarg, &c->ip4.addr_out) &&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out)	 &&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.addr_out)	 &&
			    !IN4_IS_ADDR_MULTICAST(&c->ip4.addr_out))
				break;

			die("Invalid or redundant outbound address: %s",
			    optarg);
			break;
		case 'D':
			if (!strcmp(optarg, "none")) {
				if (c->no_dns)
					die("Redundant DNS options");

				if (dns4 - c->ip4.dns || dns6 - c->ip6.dns)
					die("Conflicting DNS options");

				c->no_dns = 1;
				break;
			}

			if (c->no_dns)
				die("Conflicting DNS options");

			if (dns4 - &c->ip4.dns[0] < ARRAY_SIZE(c->ip4.dns) &&
			    inet_pton(AF_INET, optarg, dns4)) {
				dns4++;
				break;
			}

			if (dns6 - &c->ip6.dns[0] < ARRAY_SIZE(c->ip6.dns) &&
			    inet_pton(AF_INET6, optarg, dns6)) {
				dns6++;
				break;
			}

			die("Cannot use DNS address %s", optarg);
			break;
		case 'S':
			if (!strcmp(optarg, "none")) {
				if (c->no_dns_search)
					die("Redundant DNS search options");

				if (dnss != c->dns_search)
					die("Conflicting DNS search options");

				c->no_dns_search = 1;
				break;
			}

			if (c->no_dns_search)
				die("Conflicting DNS search options");

			if (dnss - c->dns_search < ARRAY_SIZE(c->dns_search)) {
				ret = snprintf(dnss->n, sizeof(*c->dns_search),
					       "%s", optarg);
				dnss++;

				if (ret > 0 &&
				    ret < (int)sizeof(*c->dns_search))
					break;
			}

			die("Cannot use DNS search domain %s", optarg);
			break;
		case '4':
			v4_only = true;
			break;
		case '6':
			v6_only = true;
			break;
		case '1':
			if (c->mode != MODE_PASST)
				die("--one-off is for passt mode only");

			if (c->one_off)
				die("Redundant --one-off option");

			c->one_off = true;
			break;
		case 't':
		case 'u':
		case 'T':
		case 'U':
			/* Handle these later, once addresses are configured */
			break;
		case '?':
		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	} while (name != -1);

	if (v4_only && v6_only)
		die("Options ipv4-only and ipv6-only are mutually exclusive");

	if (*c->sock_path && c->fd_tap >= 0)
		die("Options --socket and --fd are mutually exclusive");

	if (!ifi4 && *c->ip4.ifname_out)
		ifi4 = if_nametoindex(c->ip4.ifname_out);

	if (!ifi6 && *c->ip6.ifname_out)
		ifi6 = if_nametoindex(c->ip6.ifname_out);

	conf_ugid(runas, &uid, &gid);

	if (logfile) {
		logfile_init(c->mode == MODE_PASST ? "passt" : "pasta",
			     logfile, logsize);
	}

	nl_sock_init(c, false);
	if (!v6_only)
		c->ifi4 = conf_ip4(ifi4, &c->ip4, c->mac);
	if (!v4_only)
		c->ifi6 = conf_ip6(ifi6, &c->ip6, c->mac);
	if ((!c->ifi4 && !c->ifi6) ||
	    (*c->ip4.ifname_out && !c->ifi4) ||
	    (*c->ip6.ifname_out && !c->ifi6))
		die("External interface not usable");

	/* Inbound port options can be parsed now (after IPv4/IPv6 settings) */
	optind = 1;
	do {
		struct port_fwd *fwd;

		name = getopt_long(argc, argv, optstring, options, NULL);

		if ((name == 't' && (fwd = &c->tcp.fwd_in)) ||
		    (name == 'u' && (fwd = &c->udp.fwd_in.f))) {
			conf_ports(c, name, optarg, fwd);
		}
	} while (name != -1);

	if (c->mode == MODE_PASTA) {
		conf_pasta_ns(&netns_only, userns, netns, optind, argc, argv);
		if (!*netns) {
			long ch_pid = pasta_start_child(c, uid, gid, argc - optind, argv + optind);
			if (ch_pid > 0) {
				*userns = 0;
				snprintf(netns, PATH_MAX, "/proc/%ld/ns/net", ch_pid);
				if (!*userns)
					snprintf(userns, PATH_MAX, "/proc/%ld/ns/user",
							ch_pid);
				if (*netns && !*userns)
					netns_only = 1;
				c->foreground = 1;
				c->quiet = 1;
				c->keep_child_pid = ch_pid;
			}
		}
	} else if (optind != argc) {
		die("Extra non-option argument: %s", argv[optind]);
	}

	isolate_user(uid, gid, !netns_only, userns, c->mode);

	if (c->pasta_conf_ns)
		c->no_ra = 1;

	if (c->mode == MODE_PASTA) {
		if (*netns) {
			pasta_open_ns(c, netns);
		} else {
			pasta_start_ns(c, uid, gid,
				       argc - optind, argv + optind);
		}
	}

	if (c->mode == MODE_PASTA)
		nl_sock_init(c, true);

	/* ...and outbound port options now that namespaces are set up. */
	optind = 1;
	do {
		struct port_fwd *fwd;

		name = getopt_long(argc, argv, optstring, options, NULL);

		if ((name == 'T' && (fwd = &c->tcp.fwd_out)) ||
		    (name == 'U' && (fwd = &c->udp.fwd_out.f))) {
			conf_ports(c, name, optarg, fwd);
		}
	} while (name != -1);

	if (!c->ifi4)
		c->no_dhcp = 1;

	if (!c->ifi6) {
		c->no_ndp = 1;
		c->no_dhcpv6 = 1;
	}

	if (!c->mtu)
		c->mtu = ROUND_DOWN(ETH_MAX_MTU - ETH_HLEN, sizeof(uint32_t));

	get_dns(c);

	if (!*c->pasta_ifn) {
		if (c->ifi4)
			if_indextoname(c->ifi4, c->pasta_ifn);
		else
			if_indextoname(c->ifi6, c->pasta_ifn);
	}

	if (c->mode == MODE_PASTA) {
		c->proc_net_tcp[V4][0] = c->proc_net_tcp[V4][1] = -1;
		c->proc_net_tcp[V6][0] = c->proc_net_tcp[V6][1] = -1;
		c->proc_net_udp[V4][0] = c->proc_net_udp[V4][1] = -1;
		c->proc_net_udp[V6][0] = c->proc_net_udp[V6][1] = -1;

		if (!c->tcp.fwd_in.mode || c->tcp.fwd_in.mode == FWD_AUTO) {
			c->tcp.fwd_in.mode = FWD_AUTO;
			ns_ports_arg.proto = IPPROTO_TCP;
			NS_CALL(get_bound_ports_ns, &ns_ports_arg);
		}
		if (!c->udp.fwd_in.f.mode || c->udp.fwd_in.f.mode == FWD_AUTO) {
			c->udp.fwd_in.f.mode = FWD_AUTO;
			ns_ports_arg.proto = IPPROTO_UDP;
			NS_CALL(get_bound_ports_ns, &ns_ports_arg);
		}
		if (!c->tcp.fwd_out.mode || c->tcp.fwd_out.mode == FWD_AUTO) {
			c->tcp.fwd_out.mode = FWD_AUTO;
			get_bound_ports(c, 0, IPPROTO_TCP);
		}
		if (!c->udp.fwd_out.f.mode || c->udp.fwd_out.f.mode == FWD_AUTO) {
			c->udp.fwd_out.f.mode = FWD_AUTO;
			get_bound_ports(c, 0, IPPROTO_UDP);
		}
	} else {
		if (!c->tcp.fwd_in.mode)
			c->tcp.fwd_in.mode = FWD_NONE;
		if (!c->tcp.fwd_out.mode)
			c->tcp.fwd_out.mode = FWD_NONE;
		if (!c->udp.fwd_in.f.mode)
			c->udp.fwd_in.f.mode = FWD_NONE;
		if (!c->udp.fwd_out.f.mode)
			c->udp.fwd_out.f.mode = FWD_NONE;
	}

	if (!c->quiet)
		conf_print(c);
}

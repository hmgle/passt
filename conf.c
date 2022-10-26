// SPDX-License-Identifier: AGPL-3.0-or-later

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
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
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
 * Returns: If another @c is found in @s, returns a pointer to the
 *	    character *after* the delimiter, if no further @c is in
 *	    @s, return NULL
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
 *
 * Return: -EINVAL on parsing error, 0 otherwise
 */
static int conf_ports(const struct ctx *c, char optname, const char *optarg,
		      struct port_fwd *fwd)
{
	char addr_buf[sizeof(struct in6_addr)] = { 0 }, *addr = addr_buf;
	char buf[BUFSIZ], *spec, *ifname = NULL, *p;
	uint8_t exclude[PORT_BITMAP_SIZE] = { 0 };
	sa_family_t af = AF_UNSPEC;
	bool exclude_only = true;

	if (!strcmp(optarg, "none")) {
		if (fwd->mode)
			return -EINVAL;
		fwd->mode = FWD_NONE;
		return 0;
	}

	if (!strcmp(optarg, "auto")) {
		if (fwd->mode || c->mode != MODE_PASTA)
			return -EINVAL;
		fwd->mode = FWD_AUTO;
		return 0;
	}

	if (!strcmp(optarg, "all")) {
		unsigned i;

		if (fwd->mode || c->mode != MODE_PASST)
			return -EINVAL;
		fwd->mode = FWD_ALL;
		memset(fwd->map, 0xff, PORT_EPHEMERAL_MIN / 8);

		for (i = 0; i < PORT_EPHEMERAL_MIN; i++) {
			if (optname == 't')
				tcp_sock_init(c, 0, AF_UNSPEC, NULL, NULL, i);
			else if (optname == 'u')
				udp_sock_init(c, 0, AF_UNSPEC, NULL, NULL, i);
		}

		return 0;
	}

	if (fwd->mode > FWD_SPEC)
		return -EINVAL;

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

		if (inet_pton(AF_INET, buf, addr))
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

			if (optname == 't')
				tcp_sock_init(c, 0, af, addr, ifname, i);
			else if (optname == 'u')
				udp_sock_init(c, 0, af, addr, ifname, i);
		}

		return 0;
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

			if (optname == 't')
				tcp_sock_init(c, 0, af, addr, ifname, i);
			else if (optname == 'u')
				udp_sock_init(c, 0, af, addr, ifname, i);
		}
	} while ((p = next_chunk(p, ',')));

	return 0;
bad:
	err("Invalid port specifier %s", optarg);
	return -EINVAL;

overlap:
	err("Overlapping port specifier %s", optarg);
	return -EINVAL;
}

/**
 * get_dns() - Get nameserver addresses from local /etc/resolv.conf
 * @c:		Execution context
 */
static void get_dns(struct ctx *c)
{
	int dns4_set, dns6_set, dnss_set, dns_set, fd;
	struct in6_addr *dns6 = &c->ip6.dns[0];
	struct fqdn *s = c->dns_search;
	uint32_t *dns4 = &c->ip4.dns[0];
	struct lineread resolvconf;
	int line_len;
	char *line, *p, *end;

	dns4_set = !c->ifi4 || !!*dns4;
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
			    dns4 - &c->ip4.dns[0] < ARRAY_SIZE(c->ip4.dns) - 1 &&
			    inet_pton(AF_INET, p + 1, dns4)) {
				/* We can only access local addresses via the gw redirect */
				if (ntohl(*dns4) >> IN_CLASSA_NSHIFT == IN_LOOPBACKNET) {
					if (c->no_map_gw) {
						*dns4 = 0;
						continue;
					}
					*dns4 = c->ip4.gw;
				}
				dns4++;
				*dns4 = 0;
			}

			if (!dns6_set &&
			    dns6 - &c->ip6.dns[0] < ARRAY_SIZE(c->ip6.dns) - 1 &&
			    inet_pton(AF_INET6, p + 1, dns6)) {
				/* We can only access local addresses via the gw redirect */
				if (IN6_IS_ADDR_LOOPBACK(dns6)) {
					if (c->no_map_gw) {
						memset(dns6, 0, sizeof(*dns6));
						continue;
					}
					memcpy(dns6, &c->ip6.gw, sizeof(*dns6));
				}
				dns6++;
				memset(dns6, 0, sizeof(*dns6));
			}
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
 *
 * Return: 0 on success, negative error code otherwise
 */
static int conf_netns_opt(char *netns, const char *arg)
{
	int ret;

	if (!strchr(arg, '/')) {
		/* looks like a netns name */
		ret = snprintf(netns, PATH_MAX, "%s/%s", NETNS_RUN_DIR, arg);
	} else {
		/* otherwise assume it's a netns path */
		ret = snprintf(netns, PATH_MAX, "%s", arg);
	}

	if (ret <= 0 || ret > PATH_MAX) {
		err("Network namespace name/path %s too long");
		return -E2BIG;
	}

	return 0;
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
 *
 * Return: 0 on success, negative error code otherwise
 */
static int conf_pasta_ns(int *netns_only, char *userns, char *netns,
			 int optind, int argc, char *argv[])
{
	if (*netns_only && *userns) {
		err("Both --userns and --netns-only given");
		return -EINVAL;
	}

	if (*netns && optind != argc) {
		err("Both --netns and PID or command given");
		return -EINVAL;
	}

	if (optind + 1 == argc) {
		char *endptr;
		long pidval;

		pidval = strtol(argv[optind], &endptr, 10);
		if (!*endptr) {
			/* Looks like a pid */
			if (pidval < 0 || pidval > INT_MAX) {
				err("Invalid PID %s", argv[optind]);
				return -EINVAL;
			}

			snprintf(netns, PATH_MAX, "/proc/%ld/ns/net", pidval);
			if (!*userns)
				snprintf(userns, PATH_MAX, "/proc/%ld/ns/user",
					 pidval);
		}
	}

	/* Attaching to a netns/PID, with no userns given */
	if (*netns && !*userns)
		*netns_only = 1;

	return 0;
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
	if (!ifi)
		ifi = nl_get_ext_if(AF_INET);

	if (!ifi) {
		warn("No external routable interface for IPv4");
		return 0;
	}

	if (!ip4->gw)
		nl_route(0, ifi, AF_INET, &ip4->gw);

	if (!ip4->addr) {
		int mask_len = 0;

		nl_addr(0, ifi, AF_INET, &ip4->addr, &mask_len, NULL);
		ip4->mask = htonl(0xffffffff << (32 - mask_len));
	}

	if (!ip4->mask) {
		if (IN_CLASSA(ntohl(ip4->addr)))
			ip4->mask = htonl(IN_CLASSA_NET);
		else if (IN_CLASSB(ntohl(ip4->addr)))
			ip4->mask = htonl(IN_CLASSB_NET);
		else if (IN_CLASSC(ntohl(ip4->addr)))
			ip4->mask = htonl(IN_CLASSC_NET);
		else
			ip4->mask = 0xffffffff;
	}

	memcpy(&ip4->addr_seen, &ip4->addr, sizeof(ip4->addr_seen));

	if (MAC_IS_ZERO(mac))
		nl_link(0, ifi, mac, 0, 0);

	if (!ip4->gw || !ip4->addr || MAC_IS_ZERO(mac))
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
	info(   "    default: interface with first default route");
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
	char buf4[INET_ADDRSTRLEN], ifn[IFNAMSIZ];
	int i;

	if (c->ifi4)
		info("Outbound interface (IPv4): %s", if_indextoname(c->ifi4, ifn));
	if (c->ifi6)
		info("Outbound interface (IPv6): %s", if_indextoname(c->ifi6, ifn));
	if (c->mode == MODE_PASTA)
		info("Namespace interface: %s", c->pasta_ifn);

	info("MAC:");
	info("    host: %02x:%02x:%02x:%02x:%02x:%02x",
	     c->mac[0], c->mac[1], c->mac[2],
	     c->mac[3], c->mac[4], c->mac[5]);

	if (c->ifi4) {
		if (!c->no_dhcp) {
			info("DHCP:");
			info("    assign: %s",
			     inet_ntop(AF_INET, &c->ip4.addr, buf4, sizeof(buf4)));
			info("    mask: %s",
			     inet_ntop(AF_INET, &c->ip4.mask, buf4, sizeof(buf4)));
			info("    router: %s",
			     inet_ntop(AF_INET, &c->ip4.gw,   buf4, sizeof(buf4)));
		}

		for (i = 0; c->ip4.dns[i]; i++) {
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
		char buf6[INET6_ADDRSTRLEN];

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
 *
 * Return: 0 on success, negative error code on failure
 */
static int conf_ugid(char *runas, uid_t *uid, gid_t *gid)
{
	const char root_uid_map[] = "         0          0 4294967295";
	char buf[BUFSIZ];
	int ret;
	int fd;

	/* If user has specified --runas, that takes precedence... */
	if (runas) {
		ret = conf_runas(runas, uid, gid);
		if (ret)
			err("Invalid --runas option: %s", runas);
		return ret;
	}

	/* ...otherwise default to current user and group... */
	*uid = geteuid();
	*gid = getegid();

	/* ...as long as it's not root... */
	if (*uid)
		return 0;

	/* ...or at least not root in the init namespace... */
	if ((fd = open("/proc/self/uid_map", O_RDONLY | O_CLOEXEC)) < 0) {
		ret = -errno;
		err("Can't determine if we're in init namespace: %s",
		    strerror(-ret));
		return ret;
	}

	if (read(fd, buf, BUFSIZ) != sizeof(root_uid_map) ||
	    strncmp(buf, root_uid_map, sizeof(root_uid_map) - 1)) {
		close(fd);
		return 0;
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
	return 0;
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
		{"ns-ifname",	required_argument,	NULL,		'I' },
		{"pcap",	required_argument,	NULL,		'p' },
		{"pid",		required_argument,	NULL,		'P' },
		{"mtu",		required_argument,	NULL,		'm' },
		{"address",	required_argument,	NULL,		'a' },
		{"netmask",	required_argument,	NULL,		'n' },
		{"mac-addr",	required_argument,	NULL,		'M' },
		{"gateway",	required_argument,	NULL,		'g' },
		{"interface",	required_argument,	NULL,		'i' },
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
		{ 0 },
	};
	struct get_bound_ports_ns_arg ns_ports_arg = { .c = c };
	char userns[PATH_MAX] = { 0 }, netns[PATH_MAX] = { 0 };
	bool v4_only = false, v6_only = false;
	char *runas = NULL, *logfile = NULL;
	struct in6_addr *dns6 = c->ip6.dns;
	struct fqdn *dnss = c->dns_search;
	uint32_t *dns4 = c->ip4.dns;
	int name, ret, mask, b, i;
	const char *optstring;
	unsigned int ifi = 0;
	size_t logsize = 0;
	uid_t uid;
	gid_t gid;

	if (c->mode == MODE_PASTA) {
		c->no_dhcp_dns = c->no_dhcp_dns_search = 1;
		optstring = "dqfel:hI:p:P:m:a:n:M:g:i:D:S:46t:u:T:U:";
	} else {
		optstring = "dqfel:hs:p:P:m:a:n:M:g:i:D:S:461t:u:";
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
			if (c->mode != MODE_PASTA) {
				err("--userns is for pasta mode only");
				usage(argv[0]);
			}

			ret = snprintf(userns, sizeof(userns), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(userns)) {
				err("Invalid userns: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 3:
			if (c->mode != MODE_PASTA) {
				err("--netns is for pasta mode only");
				usage(argv[0]);
			}

			ret = conf_netns_opt(netns, optarg);
			if (ret < 0)
				usage(argv[0]);
			break;
		case 4:
			if (c->mode != MODE_PASTA) {
				err("--ns-mac-addr is for pasta mode only");
				usage(argv[0]);
			}

			for (i = 0; i < ETH_ALEN; i++) {
				errno = 0;
				b = strtol(optarg + (intptr_t)i * 3, NULL, 16);
				if (b < 0 || b > UCHAR_MAX || errno) {
					err("Invalid MAC address: %s", optarg);
					usage(argv[0]);
				}
				c->mac_guest[i] = b;
			}
			break;
		case 5:
			if (c->mode != MODE_PASTA) {
				err("--dhcp-dns is for pasta mode only");
				usage(argv[0]);
			}
			c->no_dhcp_dns = 0;
			break;
		case 6:
			if (c->mode != MODE_PASST) {
				err("--no-dhcp-dns is for passt mode only");
				usage(argv[0]);
			}
			c->no_dhcp_dns = 1;
			break;
		case 7:
			if (c->mode != MODE_PASTA) {
				err("--dhcp-search is for pasta mode only");
				usage(argv[0]);
			}
			c->no_dhcp_dns_search = 0;
			break;
		case 8:
			if (c->mode != MODE_PASST) {
				err("--no-dhcp-search is for passt mode only");
				usage(argv[0]);
			}
			c->no_dhcp_dns_search = 1;
			break;
		case 9:
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_fwd)	&&
			    inet_pton(AF_INET6, optarg, &c->ip6.dns_fwd) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_fwd)	&&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.dns_fwd))
				break;

			if (c->ip4.dns_fwd == INADDR_ANY		&&
			    inet_pton(AF_INET, optarg, &c->ip4.dns_fwd)	&&
			    c->ip4.dns_fwd != INADDR_ANY		&&
			    c->ip4.dns_fwd != INADDR_BROADCAST		&&
			    c->ip4.dns_fwd != INADDR_LOOPBACK)
				break;

			err("Invalid DNS forwarding address: %s", optarg);
			usage(argv[0]);
			break;
		case 10:
			if (c->mode != MODE_PASTA) {
				err("--no-netns-quit is for pasta mode only");
				usage(argv[0]);
			}
			c->no_netns_quit = 1;
			break;
		case 11:
			if (c->trace) {
				err("Multiple --trace options given");
				usage(argv[0]);
			}

			if (c->quiet) {
				err("Either --trace or --quiet");
				usage(argv[0]);
			}

			c->trace = c->debug = 1;
			break;
		case 12:
			if (runas) {
				err("Multiple --runas options given");
				usage(argv[0]);
			}

			runas = optarg;
			break;
		case 13:
			if (logsize) {
				err("Multiple --log-size options given");
				usage(argv[0]);
			}

			errno = 0;
			logsize = strtol(optarg, NULL, 0);

			if (logsize < LOGFILE_SIZE_MIN || errno) {
				err("Invalid --log-size: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 14:
			fprintf(stdout,
				c->mode == MODE_PASST ? "passt " : "pasta ");
			fprintf(stdout, VERSION_BLOB);
			exit(EXIT_SUCCESS);
		case 'd':
			if (c->debug) {
				err("Multiple --debug options given");
				usage(argv[0]);
			}

			if (c->quiet) {
				err("Either --debug or --quiet");
				usage(argv[0]);
			}

			c->debug = 1;
			break;
		case 'e':
			if (logfile) {
				err("Can't log to both file and stderr");
				usage(argv[0]);
			}

			if (c->stderr) {
				err("Multiple --stderr options given");
				usage(argv[0]);
			}

			c->stderr = 1;
			break;
		case 'l':
			if (c->stderr) {
				err("Can't log to both stderr and file");
				usage(argv[0]);
			}

			if (logfile) {
				err("Multiple --log-file options given");
				usage(argv[0]);
			}

			logfile = optarg;
			break;
		case 'q':
			if (c->quiet) {
				err("Multiple --quiet options given");
				usage(argv[0]);
			}

			if (c->debug) {
				err("Either --debug or --quiet");
				usage(argv[0]);
			}

			c->quiet = 1;
			break;
		case 'f':
			if (c->foreground) {
				err("Multiple --foreground options given");
				usage(argv[0]);
			}

			c->foreground = 1;
			break;
		case 's':
			if (*c->sock_path) {
				err("Multiple --socket options given");
				usage(argv[0]);
			}

			ret = snprintf(c->sock_path, UNIX_SOCK_MAX - 1, "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->sock_path)) {
				err("Invalid socket path: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'I':
			if (*c->pasta_ifn) {
				err("Multiple --ns-ifname options given");
				usage(argv[0]);
			}

			ret = snprintf(c->pasta_ifn, IFNAMSIZ - 1, "%s",
				       optarg);
			if (ret <= 0 || ret >= IFNAMSIZ - 1) {
				err("Invalid interface name: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'p':
			if (*c->pcap) {
				err("Multiple --pcap options given");
				usage(argv[0]);
			}

			ret = snprintf(c->pcap, sizeof(c->pcap), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pcap)) {
				err("Invalid pcap path: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'P':
			if (*c->pid_file) {
				err("Multiple --pid options given");
				usage(argv[0]);
			}

			ret = snprintf(c->pid_file, sizeof(c->pid_file), "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pid_file)) {
				err("Invalid PID file: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'm':
			if (c->mtu) {
				err("Multiple --mtu options given");
				usage(argv[0]);
			}

			errno = 0;
			c->mtu = strtol(optarg, NULL, 0);

			if (!c->mtu) {
				c->mtu = -1;
				break;
			}

			if (c->mtu < ETH_MIN_MTU || c->mtu > (int)ETH_MAX_MTU ||
			    errno) {
				err("Invalid MTU: %s", optarg);
				usage(argv[0]);
			}
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

			if (c->ip4.addr == INADDR_ANY			&&
			    inet_pton(AF_INET, optarg, &c->ip4.addr)	&&
			    c->ip4.addr != INADDR_ANY			&&
			    c->ip4.addr != INADDR_BROADCAST		&&
			    c->ip4.addr != INADDR_LOOPBACK		&&
			    !IN_MULTICAST(c->ip4.addr))
				break;

			err("Invalid address: %s", optarg);
			usage(argv[0]);
			break;
		case 'n':
			if (inet_pton(AF_INET, optarg, &c->ip4.mask))
				break;

			errno = 0;
			mask = strtol(optarg, NULL, 0);
			if (mask > 0 && mask <= 32 && !errno) {
				c->ip4.mask = htonl(0xffffffff << (32 - mask));
				break;
			}

			err("Invalid netmask: %s", optarg);
			usage(argv[0]);
			break;
		case 'M':
			for (i = 0; i < ETH_ALEN; i++) {
				errno = 0;
				b = strtol(optarg + (intptr_t)i * 3, NULL, 16);
				if (b < 0 || b > UCHAR_MAX || errno) {
					err("Invalid MAC address: %s", optarg);
					usage(argv[0]);
				}
				c->mac[i] = b;
			}
			break;
		case 'g':
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.gw)		&&
			    inet_pton(AF_INET6, optarg, &c->ip6.gw)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.gw)	&&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.gw))
				break;

			if (c->ip4.gw == INADDR_ANY			&&
			    inet_pton(AF_INET, optarg, &c->ip4.gw)	&&
			    c->ip4.gw != INADDR_ANY			&&
			    c->ip4.gw != INADDR_BROADCAST		&&
			    c->ip4.gw != INADDR_LOOPBACK)
				break;

			err("Invalid gateway address: %s", optarg);
			usage(argv[0]);
			break;
		case 'i':
			if (ifi) {
				err("Redundant interface: %s", optarg);
				usage(argv[0]);
			}

			if (!(ifi = if_nametoindex(optarg))) {
				err("Invalid interface name %s: %s", optarg,
				    strerror(errno));
				usage(argv[0]);
			}
			break;
		case 'D':
			if (!strcmp(optarg, "none")) {
				if (c->no_dns) {
					err("Redundant DNS options");
					usage(argv[0]);
				}

				if (dns4 - c->ip4.dns || dns6 - c->ip6.dns) {
					err("Conflicting DNS options");
					usage(argv[0]);
				}

				c->no_dns = 1;
				break;
			}

			if (c->no_dns) {
				err("Conflicting DNS options");
				usage(argv[0]);
			}

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

			err("Cannot use DNS address %s", optarg);
			usage(argv[0]);
			break;
		case 'S':
			if (!strcmp(optarg, "none")) {
				if (c->no_dns_search) {
					err("Redundant DNS search options");
					usage(argv[0]);
				}

				if (dnss != c->dns_search) {
					err("Conflicting DNS search options");
					usage(argv[0]);
				}

				c->no_dns_search = 1;
				break;
			}

			if (c->no_dns_search) {
				err("Conflicting DNS search options");
				usage(argv[0]);
			}

			if (dnss - c->dns_search < ARRAY_SIZE(c->dns_search)) {
				ret = snprintf(dnss->n, sizeof(*c->dns_search),
					       "%s", optarg);
				dnss++;

				if (ret > 0 &&
				    ret < (int)sizeof(*c->dns_search))
					break;
			}

			err("Cannot use DNS search domain %s", optarg);
			usage(argv[0]);
			break;
		case '4':
			v4_only = true;
			break;
		case '6':
			v6_only = true;
			break;
		case '1':
			if (c->mode != MODE_PASST) {
				err("--one-off is for passt mode only");
				usage(argv[0]);
			}

			if (c->one_off) {
				err("Redundant --one-off option");
				usage(argv[0]);
			}

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

	if (v4_only && v6_only) {
		err("Options ipv4-only and ipv6-only are mutually exclusive");
		usage(argv[0]);
	}

	ret = conf_ugid(runas, &uid, &gid);
	if (ret)
		usage(argv[0]);

	if (logfile) {
		logfile_init(c->mode == MODE_PASST ? "passt" : "pasta",
			     logfile, logsize);
	}

	nl_sock_init(c, false);
	if (!v6_only)
		c->ifi4 = conf_ip4(ifi, &c->ip4, c->mac);
	if (!v4_only)
		c->ifi6 = conf_ip6(ifi, &c->ip6, c->mac);
	if (!c->ifi4 && !c->ifi6) {
		err("External interface not usable");
		exit(EXIT_FAILURE);
	}

	/* Inbound port options can be parsed now (after IPv4/IPv6 settings) */
	optind = 1;
	do {
		struct port_fwd *fwd;

		name = getopt_long(argc, argv, optstring, options, NULL);

		if ((name == 't' && (fwd = &c->tcp.fwd_in)) ||
		    (name == 'u' && (fwd = &c->udp.fwd_in.f))) {
			if (!optarg || conf_ports(c, name, optarg, fwd))
				usage(argv[0]);
		}
	} while (name != -1);

	if (c->mode == MODE_PASTA) {
		if (conf_pasta_ns(&netns_only, userns, netns,
				  optind, argc, argv) < 0)
			usage(argv[0]);
	} else if (optind != argc) {
		usage(argv[0]);
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
			if (!optarg || conf_ports(c, name, optarg, fwd))
				usage(argv[0]);
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

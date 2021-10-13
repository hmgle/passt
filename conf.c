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
 *
 * #syscalls stat
 */

#define _GNU_SOURCE
#include <sched.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "util.h"
#include "passt.h"
#include "udp.h"
#include "tcp.h"
#include "netlink.h"
#include "pasta.h"

/**
 * get_bound_ports() - Get maps of ports with bound sockets
 * @c:		Execution context
 * @ns:		If set, set bitmaps for ports to tap/ns -- to init otherwise
 * @proto:	Protocol number (IPPROTO_TCP or IPPROTO_UDP)
 */
void get_bound_ports(struct ctx *c, int ns, uint8_t proto)
{
	uint8_t *udp_map, *udp_exclude, *tcp_map, *tcp_exclude;

	if (ns) {
		udp_map = c->udp.port_to_tap;
		udp_exclude = c->udp.port_to_init;
		tcp_map = c->tcp.port_to_tap;
		tcp_exclude = c->tcp.port_to_init;
	} else {
		udp_map = c->udp.port_to_init;
		udp_exclude = c->udp.port_to_tap;
		tcp_map = c->tcp.port_to_init;
		tcp_exclude = c->tcp.port_to_tap;
	}

	if (proto == IPPROTO_UDP) {
		memset(udp_map, 0, USHRT_MAX / 8);
		procfs_scan_listen("udp",  udp_map, udp_exclude);
		procfs_scan_listen("udp6", udp_map, udp_exclude);

		procfs_scan_listen("tcp",  udp_map, udp_exclude);
		procfs_scan_listen("tcp6", udp_map, udp_exclude);
	} else if (proto == IPPROTO_TCP) {
		memset(tcp_map, 0, USHRT_MAX / 8);
		procfs_scan_listen("tcp",  tcp_map, tcp_exclude);
		procfs_scan_listen("tcp6", tcp_map, tcp_exclude);
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

enum conf_port_type {
	PORT_SPEC = 1,
	PORT_NONE,
	PORT_AUTO,
	PORT_ALL,
};

static int conf_ports(struct ctx *c, char optname, const char *optarg,
		      enum conf_port_type *set)
{
	int start_src = -1, end_src = -1, start_dst = -1, end_dst = -1;
	void (*remap)(in_port_t port, in_port_t delta);
	const char *p;
	uint8_t *map;
	char *sep;

	if (optname == 't') {
		map = c->tcp.port_to_tap;
		remap = tcp_remap_to_tap;
	} else if (optname == 'T') {
		map = c->tcp.port_to_init;
		remap = tcp_remap_to_init;
	} else if (optname == 'u') {
		map = c->udp.port_to_tap;
		remap = udp_remap_to_tap;
	} else if (optname == 'U') {
		map = c->udp.port_to_init;
		remap = udp_remap_to_init;
	} else {	/* For gcc -O3 */
		return 0;
	}

	if (!strcmp(optarg, "none")) {
		if (*set)
			return -EINVAL;
		*set = PORT_NONE;
		return 0;
	}

	if (!strcmp(optarg, "auto")) {
		if (*set || c->mode != MODE_PASTA)
			return -EINVAL;
		*set = PORT_AUTO;
		return 0;
	}

	if (!strcmp(optarg, "all")) {
		if (*set || c->mode != MODE_PASST)
			return -EINVAL;
		*set = PORT_ALL;
		memset(map, 0xff, PORT_EPHEMERAL_MIN / 8);
		return 0;
	}

	if (*set > PORT_SPEC)
		return -EINVAL;

	*set = PORT_SPEC;

	if (strspn(optarg, "0123456789-,:") != strlen(optarg)) {
		err("Invalid port specifier %s", optarg);
		return -EINVAL;
	}

	p = optarg;
	do {
		int i, port;

		port = strtol(p, &sep, 10);
		if (sep == p)
			break;

		if (port < 0 || port > USHRT_MAX || errno)
			goto bad;

		/* -p 22
		 *    ^ start_src	end_src == start_dst == end_dst == -1
		 *
		 * -p 22-25
		 *    |  ^ end_src
		 *     ` start_src	start_dst == end_dst == -1
		 *
		 * -p 80:8080
		 *    |  ^ start_dst
		 *     ` start_src	end_src == end_dst == -1
		 *
		 * -p 22-80:8022-8080
		 *    |  |  |    ^ end_dst
		 *    |  |   ` start_dst
		 *    |   ` end_dst
		 *     ` start_src
		 */
		switch (*sep) {
		case '-':
			if (start_src == -1) {		/* 22-... */
				start_src = port;
			} else {
				if (!end_src)		/* 22:8022-8080 */
					goto bad;
				start_dst = port;	/* 22-80:8022-... */
			}
			break;
		case ':':
			if (start_src == -1)		/* 80:... */
				start_src = end_src = port;
			else if (end_src == -1)		/* 22-80:... */
				end_src = port;
			else				/* 22-80:8022:... */
				goto bad;
			break;
		case ',':
		case 0:
			if (start_src == -1)		/* 80 */
				start_src = end_src = port;
			else if (end_src == -1)		/* 22-25 */
				end_src = port;
			else if (start_dst == -1)	/* 80:8080 */
				start_dst = end_dst = port;
			else if (end_dst == -1)		/* 22-80:8022-8080 */
				end_dst = port;
			else
				goto bad;

			if (start_src > end_src)	/* 80-22 */
				goto bad;

			if (start_dst > end_dst)	/* 22-80:8080:8022 */
				goto bad;

			if (end_dst != -1 &&
			    end_dst - start_dst != end_src - start_src)
				goto bad;		/* 22-81:8022:8080 */

			for (i = start_src; i <= end_src; i++) {
				if (bitmap_isset(map, i))
					goto overlap;

				bitmap_set(map, i);

				if (start_dst == -1)	/* 22 or 22-80 */
					continue;

				/* 80:8080 or 22-80:8080:8080 */
				remap(i, (in_port_t)(start_dst - start_src));
			}

			start_src = end_src = start_dst = end_dst = -1;
			break;
		}
		p = sep + 1;
	} while (*sep);

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
	int dns4_set, dns6_set, dnss_set, dns_set;
	struct in6_addr *dns6 = &c->dns6[0];
	struct fqdn *s = c->dns_search;
	uint32_t *dns4 = &c->dns4[0];
	char buf[BUFSIZ], *p, *end;
	FILE *r;

	dns4_set = !c->v4  || !!*dns4;
	dns6_set = !c->v6  || !IN6_IS_ADDR_UNSPECIFIED(dns6);
	dnss_set = !!*s->n || c->no_dns_search;
	dns_set = dns4_set || dns6_set || c->no_dns;

	if (dns_set && dnss_set)
		return;

	r = fopen("/etc/resolv.conf", "r");
	if (!r)
		goto out;

	while (fgets(buf, BUFSIZ, r)) {
		if (!dns_set && strstr(buf, "nameserver ") == buf) {
			p = strrchr(buf, ' ');
			if (!p)
				continue;

			end = strpbrk(buf, "%\n");
			if (end)
				*end = 0;

			if (!dns4_set &&
			    dns4 - &c->dns4[0] < ARRAY_SIZE(c->dns4) - 1 &&
			    inet_pton(AF_INET, p + 1, dns4)) {
				dns4++;
				*dns4 = 0;
			}

			if (!dns6_set &&
			    dns6 - &c->dns6[0] < ARRAY_SIZE(c->dns6) - 1 &&
			    inet_pton(AF_INET6, p + 1, dns6)) {
				dns6++;
				memset(dns6, 0, sizeof(*dns6));
			}
		} else if (!dnss_set && strstr(buf, "search ") == buf &&
			   s == c->dns_search) {
			end = strpbrk(buf, "\n");
			if (end)
				*end = 0;

			p = strtok(buf, " \t");
			while (s - c->dns_search < ARRAY_SIZE(c->dns_search) - 1
			       && (p = strtok(NULL, " \t"))) {
				strncpy(s->n, p, sizeof(c->dns_search[0]));
				s++;
				*s->n = 0;
			}
		}
	}

	fclose(r);

out:
	if (!dns_set && dns4 == c->dns4 && dns6 == c->dns6)
		warn("Couldn't get any nameserver address");
}

/**
 * conf_ns_check() - Check if we can enter configured namespaces
 * @arg:	Execution context
 *
 * Return: 0
 */
static int conf_ns_check(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	if ((!c->netns_only && setns(c->pasta_userns_fd, 0)) ||
	    setns(c->pasta_netns_fd, 0))
		c->pasta_userns_fd = c->pasta_netns_fd = -1;

	return 0;

}

/**
 * conf_ns_opt() - Open network, user namespaces descriptors from configuration
 * @c:			Execution context
 * @nsdir:		--nsrun-dir argument, can be an empty string
 * @conf_userns:	--userns argument, can be an empty string
 * @optarg:		PID, path or name of namespace
 *
 * Return: 0 on success, negative error code otherwise
 */
static int conf_ns_opt(struct ctx *c,
		       char *nsdir, char *conf_userns, const char *optarg)
{
	char userns[PATH_MAX], netns[PATH_MAX];
	int ufd = 0, nfd = 0, try, ret;
	char *endptr;
	pid_t pid;

	if (c->netns_only && *conf_userns) {
		err("Both --userns and --netns-only given");
		return -EINVAL;
	}

	/* It might be a PID, a netns path, or a netns name */
	for (try = 0; try < 3; try++) {
		if (try == 0) {
			pid = strtol(optarg, &endptr, 10);
			if (*endptr || pid > INT_MAX)
				continue;

			if (!*conf_userns && !c->netns_only) {
				ret = snprintf(userns, PATH_MAX,
					       "/proc/%i/ns/user", pid);
				if (ret <= 0 || ret > (int)sizeof(userns))
					continue;
			}
			ret = snprintf(netns, PATH_MAX, "/proc/%i/ns/net", pid);
			if (ret <= 0 || ret > (int)sizeof(netns))
				continue;
		} else if (try == 1) {
			if (!*conf_userns)
				c->netns_only = 1;

			ret = snprintf(netns, PATH_MAX, "%s", optarg);
			if (ret <= 0 || ret > (int)sizeof(userns))
				continue;
		} else if (try == 2) {
			ret = snprintf(netns, PATH_MAX, "%s/%s",
				 *nsdir ? nsdir : NETNS_RUN_DIR, optarg);
			if (ret <= 0 || ret > (int)sizeof(netns))
				continue;
		}

		if (!c->netns_only) {
			if (*conf_userns)
				ufd = open(conf_userns, O_RDONLY);
			else if (*userns)
				ufd = open(userns, O_RDONLY);
		}

		nfd = open(netns, O_RDONLY);

		if (nfd >= 0 && ufd >= 0) {
			c->pasta_netns_fd = nfd;
			c->pasta_userns_fd = ufd;

			NS_CALL(conf_ns_check, c);
			if (c->pasta_netns_fd >= 0)
				return 0;
		}

		if (nfd > 0)
			close(nfd);

		if (ufd > 0)
			close(ufd);
	}

	return -ENOENT;
}

/**
 * conf_ip() - Verify or detect IPv4/IPv6 support, get relevant addresses
 * @c:		Execution context
 */
static void conf_ip(struct ctx *c)
{
	int v4, v6;

	if (c->v4) {
		c->v4		= IP_VERSION_ENABLED;
		v4		= IP_VERSION_PROBE;
		v6 = c->v6	= IP_VERSION_DISABLED;
	} else if (c->v6) {
		c->v6		= IP_VERSION_ENABLED;
		v6		= IP_VERSION_PROBE;
		v4 = c->v4	= IP_VERSION_DISABLED;
	} else {
		c->v4 = c->v6	= IP_VERSION_ENABLED;
		v4 = v6		= IP_VERSION_PROBE;
	}

	if (!c->ifi)
		c->ifi = nl_get_ext_if(&v4, &v6);

	if (v4 != IP_VERSION_DISABLED) {
		if (!c->gw4)
			nl_route(0, c->ifi, AF_INET, &c->gw4);

		if (!c->addr4) {
			nl_addr(0, c->ifi, AF_INET, &c->addr4, 0, NULL);
			if (!c->mask4) {
				if (IN_CLASSA(ntohl(c->addr4)))
					c->mask4 = htonl(IN_CLASSA_NET);
				else if (IN_CLASSB(ntohl(c->addr4)))
					c->mask4 = htonl(IN_CLASSB_NET);
				else if (IN_CLASSC(ntohl(c->addr4)))
					c->mask4 = htonl(IN_CLASSC_NET);
				else
					c->mask4 = 0xffffffff;
			}
		}

		memcpy(&c->addr4_seen, &c->addr4, sizeof(c->addr4_seen));

		if (!memcmp(c->mac, MAC_ZERO, ETH_ALEN))
			nl_link(0, c->ifi, c->mac, 0);
	}

	if (c->mode == MODE_PASST)
		memset(&c->mac_guest, 0xff, sizeof(c->mac_guest));

	if (v6 != IP_VERSION_DISABLED) {
		if (IN6_IS_ADDR_UNSPECIFIED(&c->gw6))
			nl_route(0, c->ifi, AF_INET6, &c->gw6);

		nl_addr(0, c->ifi, AF_INET6,
			IN6_IS_ADDR_UNSPECIFIED(&c->addr6) ? &c->addr6 : NULL,
			0, &c->addr6_ll);

		memcpy(&c->addr6_seen, &c->addr6, sizeof(c->addr4_seen));
		memcpy(&c->addr6_ll_seen, &c->addr6, sizeof(c->addr4_seen));
	}

	if (!c->gw4 || !c->addr4 ||
	    !memcmp(c->mac, ((uint8_t [ETH_ALEN]){ 0 }), ETH_ALEN))
		v4 = IP_VERSION_DISABLED;
	else
		v4 = IP_VERSION_ENABLED;

	if (IN6_IS_ADDR_UNSPECIFIED(&c->gw6) ||
	    IN6_IS_ADDR_UNSPECIFIED(&c->addr6) ||
	    IN6_IS_ADDR_UNSPECIFIED(&c->addr6_ll))
		v6 = IP_VERSION_DISABLED;
	else
		v6 = IP_VERSION_ENABLED;

	if ((v4 == IP_VERSION_DISABLED) && (v6 == IP_VERSION_DISABLED)) {
		err("External interface not usable");
		exit(EXIT_FAILURE);
	}

	c->v4 = v4;
	c->v6 = v6;
}

/**
 * usage() - Print usage and exit
 * @name:	Executable name
 */
static void usage(const char *name)
{
	if (strstr(name, "pasta") || strstr(name, "passt4netns")) {
		info("Usage: %s [OPTION]... [PID|PATH|NAME]", name);
		info("");
		info("Without PID|PATH|NAME, run the default shell in a new");
		info("network and user namespace, and connect it via pasta.");
	} else {
		info("Usage: %s [OPTION]...", name);
	}
	info("");

	info(   "  -d, --debug		Be verbose, don't run in background");
	info(   "  -q, --quiet		Don't print informational messages");
	info(   "  -f, --foreground	Don't run in background");
	info(   "    default: run in background if started from a TTY");
	info(   "  -e, --stderr		Log to stderr too");
	info(   "    default: log to system logger only if started from a TTY");
	info(   "  -h, --help		Display this help message and exit");

	if (strstr(name, "pasta") || strstr(name, "passt4netns")) {
		info(   "  -I, --ns-ifname NAME	namespace interface name");
		info(   "    default: same interface name as external one");
	} else {
		info(   "  -s, --socket PATH	UNIX domain socket path");
		info(   "    default: probe free path starting from "
		     UNIX_SOCK_PATH, 1);
	}

	info(   "  -p, --pcap [FILE]	Log tap-facing traffic to pcap file");
	info(   "    if FILE is not given, log to:");

	if (strstr(name, "pasta") || strstr(name, "passt4netns"))
		info("      /tmp/pasta_ISO8601-TIMESTAMP_INSTANCE-NUMBER.pcap");
	else
		info("      /tmp/passt_ISO8601-TIMESTAMP_INSTANCE-NUMBER.pcap");

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
	info(   "  -D, --dns ADDR	Pass IPv4 or IPv6 address as DNS");
	info(   "    can be specified multiple times");
	info(   "    a single, empty option disables DNS information");
	if (strstr(name, "pasta") || strstr(name, "passt4netns"))
		info(   "    default: don't send any addresses");
	else
		info(   "    default: use addresses from /etc/resolv.conf");

	info(   "  -S, --search LIST	Space-separated list, search domains");
	info(   "    a single, empty option disables the DNS search list");
	if (strstr(name, "pasta") || strstr(name, "passt4netns"))
		info(   "    default: don't send any search list");
	else
		info(   "    default: use search list from /etc/resolv.conf");

	info(   "  --no-tcp		Disable TCP protocol handler");
	info(   "  --no-udp		Disable UDP protocol handler");
	info(   "  --no-icmp		Disable ICMP/ICMPv6 protocol handler");
	info(   "  --no-dhcp		Disable DHCP server");
	info(   "  --no-ndp		Disable NDP responses");
	info(   "  --no-dhcpv6		Disable DHCPv6 server");
	info(   "  --no-ra		Disable router advertisements");
	info(   "  -4, --ipv4-only	Enable IPv4 operation only");
	info(   "  -6, --ipv6-only	Enable IPv6 operation only");

	if (strstr(name, "pasta") || strstr(name, "passt4netns"))
		goto pasta_opts;

	info(   "  -t, --tcp-ports SPEC	TCP port forwarding to guest");
	info(   "    can be specified multiple times");
	info(   "    SPEC can be:");
	info(   "      'none': don't forward any ports");
	info(   "      'all': forward all unbound, non-ephemeral ports");
	info(   "      a comma-separated list, optionally ranged with '-'");
	info(   "        and optional target ports after ':'. Examples:");
	info(   "        -t 22		Forward local port 22 to 22 on guest");
	info(   "        -t 22:23	Forward local port 22 to 23 on guest");
	info(   "        -t 22,25	Forward ports 22, 25 to ports 22, 25");
	info(   "        -t 22-80  	Forward ports 22 to 80");
	info(   "        -t 22-80:32-90	Forward ports 22 to 80 to");
	info(   "			corresponding port numbers plus 10");
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
	info(   "        and optional target ports after ':'. Examples:");
	info(   "        -t 22	Forward local port 22 to port 22 in netns");
	info(   "        -t 22:23	Forward local port 22 to port 23");
	info(   "        -t 22,25	Forward ports 22, 25 to ports 22, 25");
	info(   "        -t 22-80	Forward ports 22 to 80");
	info(   "        -t 22-80:32-90	Forward ports 22 to 80 to");
	info(   "			corresponding port numbers plus 10");
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
	info(   "  --netns-only		Don't join or create user namespace");
	info(   "    implied if PATH or NAME are given without --userns");
	info(   "  --nsrun-dir		Directory for nsfs mountpoints");
	info(   "    default: " NETNS_RUN_DIR);
	info(   "  --config-net		Configure tap interface in namespace");
	info(   "  --ns-mac-addr ADDR	Set MAC address on tap interface");

	exit(EXIT_FAILURE);
}

void conf_print(struct ctx *c)
{
	char buf6[INET6_ADDRSTRLEN], buf4[INET_ADDRSTRLEN], ifn[IFNAMSIZ];
	int i;

	if (c->mode == MODE_PASTA) {
		info("Outbound interface: %s, namespace interface: %s",
		     if_indextoname(c->ifi, ifn), c->pasta_ifn);
	} else {
		info("Outbound interface: %s", if_indextoname(c->ifi, ifn));
	}

	if (c->v4) {
		info("ARP:");
		info("    address: %02x:%02x:%02x:%02x:%02x:%02x",
		     c->mac[0], c->mac[1], c->mac[2],
		     c->mac[3], c->mac[4], c->mac[5]);

		if (!c->no_dhcp) {
			info("DHCP:");
			info("    assign: %s",
			     inet_ntop(AF_INET, &c->addr4, buf4, sizeof(buf4)));
			info("    mask: %s",
			     inet_ntop(AF_INET, &c->mask4, buf4, sizeof(buf4)));
			info("    router: %s",
			     inet_ntop(AF_INET, &c->gw4,   buf4, sizeof(buf4)));
		}
	}

	if (!c->no_dns && !(c->no_dhcp && c->no_ndp && c->no_dhcpv6)) {
		for (i = 0; c->dns4[i]; i++) {
			if (!i)
				info("    DNS:");
			inet_ntop(AF_INET, &c->dns4[i], buf4, sizeof(buf4));
			info("        %s", buf4);
		}
	}

	if (!c->no_dns_search && !(c->no_dhcp && c->no_ndp && c->no_dhcpv6)) {
		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("        search:");
			info("            %s", c->dns_search[i].n);
		}
	}

	if (c->v6) {
		if (!c->no_ndp && !c->no_dhcpv6)
			info("NDP/DHCPv6:");
		else if (!c->no_ndp)
			info("DHCPv6:");
		else if (!c->no_dhcpv6)
			info("NDP:");
		else
			return;

		info("    assign: %s",
		     inet_ntop(AF_INET6, &c->addr6, buf6, sizeof(buf6)));
		info("    router: %s",
		     inet_ntop(AF_INET6, &c->gw6,   buf6, sizeof(buf6)));
		info("    our link-local: %s",
		     inet_ntop(AF_INET6, &c->addr6_ll, buf6, sizeof(buf6)));

		for (i = 0; !IN6_IS_ADDR_UNSPECIFIED(&c->dns6[i]); i++) {
			if (!i)
				info("    DNS:");
			inet_ntop(AF_INET6, &c->dns6[i], buf6, sizeof(buf6));
			info("        %s", buf6);
		}

		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("        search:");
			info("            %s", c->dns_search[i].n);
		}
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
	struct option options[] = {
		{"debug",	no_argument,		NULL,		'd' },
		{"quiet",	no_argument,		NULL,		'q' },
		{"foreground",	no_argument,		NULL,		'f' },
		{"stderr",	no_argument,		&c->stderr,	1 },
		{"help",	no_argument,		NULL,		'h' },
		{"socket",	required_argument,	NULL,		's' },
		{"ns-ifname",	required_argument,	NULL,		'I' },
		{"pcap",	optional_argument,	NULL,		'p' },
		{"mtu",		required_argument,	NULL,		'm' },
		{"address",	required_argument,	NULL,		'a' },
		{"netmask",	required_argument,	NULL,		'n' },
		{"mac-addr",	required_argument,	NULL,		'M' },
		{"gateway",	required_argument,	NULL,		'g' },
		{"interface",	required_argument,	NULL,		'i' },
		{"dns",		optional_argument,	NULL,		'D' },
		{"search",	optional_argument,	NULL,		'S' },
		{"no-tcp",	no_argument,		&c->no_tcp,	1 },
		{"no-udp",	no_argument,		&c->no_udp,	1 },
		{"no-icmp",	no_argument,		&c->no_icmp,	1 },
		{"no-dhcp",	no_argument,		&c->no_dhcp,	1 },
		{"no-dhcpv6",	no_argument,		&c->no_dhcpv6,	1 },
		{"no-ndp",	no_argument,		&c->no_ndp,	1 },
		{"no-ra",	no_argument,		&c->no_ra,	1 },
		{"ipv4-only",	no_argument,		&c->v4,		'4' },
		{"ipv6-only",	no_argument,		&c->v6,		'6' },
		{"tcp-ports",	required_argument,	NULL,		't' },
		{"udp-ports",	required_argument,	NULL,		'u' },
		{"tcp-ns",	required_argument,	NULL,		'T' },
		{"udp-ns",	required_argument,	NULL,		'U' },
		{"userns",	required_argument,	NULL,		2 },
		{"netns-only",	no_argument,		&c->netns_only,	1 },
		{"nsrun-dir",	required_argument,	NULL,		3 },
		{"config-net",	no_argument,		&c->pasta_conf_ns, 1 },
		{"ns-mac-addr",	required_argument,	NULL,		4 },
		{ 0 },
	};
	struct get_bound_ports_ns_arg ns_ports_arg = { .c = c };
	char nsdir[PATH_MAX] = { 0 }, userns[PATH_MAX] = { 0 };
	enum conf_port_type tcp_tap = 0, tcp_init = 0;
	enum conf_port_type udp_tap = 0, udp_init = 0;
	struct fqdn *dnss = c->dns_search;
	struct in6_addr *dns6 = c->dns6;
	int name, ret, mask, b, i;
	uint32_t *dns4 = c->dns4;

	do {
		enum conf_port_type *set = NULL;
		const char *optstring;

		if (c->mode == MODE_PASST)
			optstring = "dqfehs:p::m:a:n:M:g:i:D::S::46t:u:";
		else
			optstring = "dqfehI:p::m:a:n:M:g:i:D::S::46t:u:T:U:";

		name = getopt_long(argc, argv, optstring, options, NULL);

		if ((name == 'p' || name == 'D' || name == 'S') && !optarg &&
		    optind < argc && *argv[optind] && *argv[optind] != '-') {
			if (c->mode == MODE_PASTA) {
				if (conf_ns_opt(c, nsdir, userns, argv[optind]))
					optarg = argv[optind++];
			} else {
				optarg = argv[optind++];
			}
		}

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
				err("--nsrun-dir is for pasta mode only");
				usage(argv[0]);
			}

			ret = snprintf(nsdir, sizeof(nsdir), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(nsdir)) {
				err("Invalid nsrun-dir: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 4:
			if (c->mode != MODE_PASTA) {
				err("--ns-mac-addr is for pasta mode only");
				usage(argv[0]);
			}

			for (i = 0; i < ETH_ALEN; i++) {
				errno = 0;
				b = strtol(optarg + i * 3, NULL, 16);
				if (b < 0 || b > UCHAR_MAX || errno) {
					err("Invalid MAC address: %s", optarg);
					usage(argv[0]);
				}
				c->mac_guest[i] = b;
			}
			break;
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
			c->foreground = 1;
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
			if (c->foreground && !c->debug) {
				err("Multiple --foreground options given");
				usage(argv[0]);
			}

			c->foreground = 1;
			break;
		case '?':
		case 'h':
			usage(argv[0]);
			break;
		case 's':
			if (*c->sock_path) {
				err("Multiple --socket options given");
				usage(argv[0]);
			}

			ret = snprintf(c->sock_path, sizeof(c->sock_path), "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pcap)) {
				err("Invalid socket path: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'I':
			if (*c->pasta_ifn) {
				err("Multiple --ns-ifname options given");
				usage(argv[0]);
			}

			ret = snprintf(c->pasta_ifn, sizeof(c->pasta_ifn), "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pasta_ifn)) {
				err("Invalid interface name: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'p':
			if (*c->pcap) {
				err("Multiple --pcap options given");
				usage(argv[0]);
			}

			if (!optarg) {
				*c->pcap = 1;
				break;
			}

			ret = snprintf(c->pcap, sizeof(c->pcap), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pcap)) {
				err("Invalid pcap path: %s", optarg);
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
			if (IN6_IS_ADDR_UNSPECIFIED(&c->addr6)		&&
			    inet_pton(AF_INET6, optarg, &c->addr6)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->addr6)		&&
			    !IN6_IS_ADDR_LOOPBACK(&c->addr6)		&&
			    !IN6_IS_ADDR_V4MAPPED(&c->addr6)		&&
			    !IN6_IS_ADDR_V4COMPAT(&c->addr6)		&&
			    !IN6_IS_ADDR_MULTICAST(&c->addr6))
				break;

			if (c->addr4 == INADDR_ANY			&&
			    inet_pton(AF_INET, optarg, &c->addr4)	&&
			    c->addr4 != INADDR_ANY			&&
			    c->addr4 != INADDR_BROADCAST		&&
			    c->addr4 != INADDR_LOOPBACK			&&
			    !IN_MULTICAST(c->addr4))
				break;

			err("Invalid address: %s", optarg);
			usage(argv[0]);
			break;
		case 'n':
			if (inet_pton(AF_INET, optarg, &c->mask4))
				break;

			errno = 0;
			mask = strtol(optarg, NULL, 0);
			if (mask >= 0 && mask <= 32 && !errno) {
				c->mask4 = htonl(0xffffffff << (32 - mask));
				break;
			}

			err("Invalid netmask: %s", optarg);
			usage(argv[0]);
			break;
		case 'M':
			for (i = 0; i < ETH_ALEN; i++) {
				errno = 0;
				b = strtol(optarg + i * 3, NULL, 16);
				if (b < 0 || b > UCHAR_MAX || errno) {
					err("Invalid MAC address: %s", optarg);
					usage(argv[0]);
				}
				c->mac[i] = b;
			}
			break;
		case 'g':
			if (IN6_IS_ADDR_UNSPECIFIED(&c->gw6)		&&
			    inet_pton(AF_INET6, optarg, &c->gw6)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->gw6)		&&
			    !IN6_IS_ADDR_LOOPBACK(&c->gw6))
				break;

			if (c->gw4 == INADDR_ANY			&&
			    inet_pton(AF_INET, optarg, &c->gw4)		&&
			    c->gw4 != INADDR_ANY			&&
			    c->gw4 != INADDR_BROADCAST			&&
			    c->gw4 != INADDR_LOOPBACK)
				break;

			err("Invalid gateway address: %s", optarg);
			usage(argv[0]);
			break;
		case 'i':
			if (c->ifi) {
				err("Redundant interface: %s", optarg);
				usage(argv[0]);
			}

			if (!(c->ifi = if_nametoindex(optarg))) {
				err("Invalid interface name %s: %s", optarg,
				    strerror(errno));
				usage(argv[0]);
			}
			break;
		case 'D':
			if (c->no_dns ||
			    (!optarg && (dns4 - c->dns4 || dns6 - c->dns6))) {
				err("Empty and non-empty DNS options given");
				usage(argv[0]);
			}

			if (!optarg) {
				c->no_dns = 1;
				break;
			}

			if (dns4 - &c->dns4[0] < ARRAY_SIZE(c->dns4) &&
			    inet_pton(AF_INET, optarg, dns4)) {
				dns4++;
				break;
			}

			if (dns6 - &c->dns6[0] < ARRAY_SIZE(c->dns6) &&
			    inet_pton(AF_INET6, optarg, dns6)) {
				dns6++;
				break;
			}

			err("Cannot use DNS address %s", optarg);
			usage(argv[0]);
			break;
		case 'S':
			if (c->no_dns_search ||
			    (!optarg && dnss != c->dns_search)) {
				err("Empty and non-empty DNS search given");
				usage(argv[0]);
			}

			if (!optarg) {
				c->no_dns_search = 1;
				break;
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
			c->v4 = 1;
			break;
		case '6':
			c->v6 = 1;
			break;
		case 't':
		case 'u':
		case 'T':
		case 'U':
			if (name == 't')
				set = &tcp_tap;
			else if (name == 'T')
				set = &tcp_init;
			else if (name == 'u')
				set = &udp_tap;
			else if (name == 'U')
				set = &udp_init;

			if (conf_ports(c, name, optarg, set))
				usage(argv[0]);

			break;
		}
	} while (name != -1);

	if (c->mode == MODE_PASTA && optind + 1 == argc) {
		ret = conf_ns_opt(c, nsdir, userns, argv[optind]);
		if (ret == -ENOENT)
			err("Namespace %s not found", argv[optind]);
		if (ret < 0)
			usage(argv[0]);
	} else if (c->mode == MODE_PASTA && *userns && optind == argc) {
		err("--userns requires PID, PATH or NAME");
		usage(argv[0]);
	} else if (optind != argc) {
		usage(argv[0]);
	}

	if (c->v4 && c->v6) {
		err("Options ipv4-only and ipv6-only are mutually exclusive");
		usage(argv[0]);
	}

	if (c->mode == MODE_PASTA && !c->pasta_netns_fd)
		pasta_start_ns(c);

	if (nl_sock_init(c)) {
		err("Failed to get netlink socket");
		exit(EXIT_FAILURE);
	}

	conf_ip(c);

	if (!c->v4)
		c->no_dhcp = 1;

	if (!c->v6) {
		c->no_ndp = 1;
		c->no_dhcpv6 = 1;
	}

	if (!c->mtu)
		c->mtu = ROUND_DOWN(ETH_MAX_MTU - ETH_HLEN, sizeof(uint32_t));

	if (c->mode == MODE_PASTA && dns4 == c->dns4 && dns6 == c->dns6)
		c->no_dns = 1;
	if (c->mode == MODE_PASTA && dnss == c->dns_search)
		c->no_dns_search = 1;
	get_dns(c);

	if (!*c->pasta_ifn)
		if_indextoname(c->ifi, c->pasta_ifn);

#ifdef PASST_LEGACY_NO_OPTIONS
	if (c->mode == MODE_PASST) {
		c->foreground = 1;
		c->stderr = 1;

		if (!tcp_tap) {
			memset(c->tcp.port_to_tap, 0xff,
			       PORT_EPHEMERAL_MIN / 8);
		}
	}
#endif

	c->tcp.ns_detect_ports   = c->udp.ns_detect_ports   = 0;
	c->tcp.init_detect_ports = c->udp.init_detect_ports = 0;

	if (c->mode == MODE_PASTA) {
		if (!tcp_tap || tcp_tap == PORT_AUTO) {
			c->tcp.ns_detect_ports = 1;
			ns_ports_arg.proto = IPPROTO_TCP;
			NS_CALL(get_bound_ports_ns, &ns_ports_arg);
		}
		if (!udp_tap || udp_tap == PORT_AUTO) {
			c->udp.ns_detect_ports = 1;
			ns_ports_arg.proto = IPPROTO_UDP;
			NS_CALL(get_bound_ports_ns, &ns_ports_arg);
		}
		if (!tcp_init || tcp_init == PORT_AUTO) {
			c->tcp.init_detect_ports = 1;
			get_bound_ports(c, 0, IPPROTO_TCP);
		}
		if (!udp_init || udp_init == PORT_AUTO) {
			c->udp.init_detect_ports = 1;
			get_bound_ports(c, 0, IPPROTO_UDP);
		}
	}

	conf_print(c);
}

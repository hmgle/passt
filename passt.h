/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PASST_H
#define PASST_H

#define UNIX_SOCK_MAX		100
#define UNIX_SOCK_PATH		"/tmp/passt_%i.socket"

/**
 * struct tap_msg - Generic message descriptor for arrays of messages
 * @pkt_buf_offset:	Offset from @pkt_buf
 * @len:		Message length, with L2 headers
 */
struct tap_msg {
	uint32_t pkt_buf_offset;
	uint16_t len;
};

/**
 * struct tap_l4_msg - Layer-4 message descriptor for protocol handlers
 * @pkt_buf_offset:	Offset of message from @pkt_buf
 * @l4_len:		Length of Layer-4 payload, host order
 */
struct tap_l4_msg {
	uint32_t pkt_buf_offset;
	uint16_t l4_len;
};

union epoll_ref;

#include <stdbool.h>

#include "packet.h"
#include "icmp.h"
#include "port_fwd.h"
#include "tcp.h"
#include "udp.h"
#include "socks.h"

/**
 * union epoll_ref - Breakdown of reference for epoll socket bookkeeping
 * @proto:	IP protocol number
 * @s:		Socket number (implies 2^24-1 limit on number of descriptors)
 * @tcp:	TCP-specific reference part
 * @udp:	UDP-specific reference part
 * @icmp:	ICMP-specific reference part
 * @data:	Data handled by protocol handlers
 * @u64:	Opaque reference for epoll_ctl() and epoll_wait()
 */
union epoll_ref {
	struct {
		int32_t		proto:8,
#define SOCKET_REF_BITS		24
#define SOCKET_MAX		MAX_FROM_BITS(SOCKET_REF_BITS)
				s:SOCKET_REF_BITS;
		union {
			union tcp_epoll_ref tcp;
			union udp_epoll_ref udp;
			union icmp_epoll_ref icmp;
			uint32_t data;
		} p;
	} r;
	uint64_t u64;
};

#define TAP_BUF_BYTES							\
	ROUND_DOWN(((ETH_MAX_MTU + sizeof(uint32_t)) * 128), PAGE_SIZE)
#define TAP_BUF_FILL		(TAP_BUF_BYTES - ETH_MAX_MTU - sizeof(uint32_t))
#define TAP_MSGS							\
	DIV_ROUND_UP(TAP_BUF_BYTES, ETH_ZLEN - 2 * ETH_ALEN + sizeof(uint32_t))

#define PKT_BUF_BYTES		MAX(TAP_BUF_BYTES, 0)
extern char pkt_buf		[PKT_BUF_BYTES];

extern char *ip_proto_str[];
#define IP_PROTO_STR(n)							\
	(((uint8_t)(n) <= IPPROTO_SCTP && ip_proto_str[(n)]) ?		\
			  ip_proto_str[(n)] : "?")

#include <resolv.h>	/* For MAXNS below */

/**
 * struct fqdn - Representation of fully-qualified domain name
 * @n:		Domain name string
 */
struct fqdn {
	char n[NS_MAXDNAME];
};

#include <net/if.h>
#include <linux/un.h>

enum passt_modes {
	MODE_PASST,
	MODE_PASTA,
};

/**
 * struct ip4_ctx - IPv4 execution context
 * @addr:		IPv4 address for external, routable interface
 * @addr_seen:		Latest IPv4 address seen as source from tap
 * @prefixlen:		IPv4 prefix length (netmask)
 * @gw:			Default IPv4 gateway, network order
 * @dns:		DNS addresses for DHCP, zero-terminated, network order
 * @dns_match:		Forward DNS query if sent to this address, network order
 * @dns_host:		Use this DNS on the host for forwarding, network order
 * @addr_out:		Optional source address for outbound traffic
 * @ifname_out:		Optional interface name to bind outbound sockets to
 */
struct ip4_ctx {
	struct in_addr addr;
	struct in_addr addr_seen;
	int prefix_len;
	struct in_addr gw;
	struct in_addr dns[MAXNS + 1];
	struct in_addr dns_match;
	struct in_addr dns_host;
	struct in_addr dns_redirect;

	struct in_addr addr_out;
	char ifname_out[IFNAMSIZ];
};

/**
 * struct ip6_ctx - IPv6 execution context
 * @addr:		IPv6 address for external, routable interface
 * @addr_ll:		Link-local IPv6 address on external, routable interface
 * @addr_seen:		Latest IPv6 global/site address seen as source from tap
 * @addr_ll_seen:	Latest IPv6 link-local address seen as source from tap
 * @gw:			Default IPv6 gateway
 * @dns:		DNS addresses for DHCPv6 and NDP, zero-terminated
 * @dns_match:		Forward DNS query if sent to this address
 * @dns_host:		Use this DNS on the host for forwarding
 * @addr_out:		Optional source address for outbound traffic
 * @ifname_out:		Optional interface name to bind outbound sockets to
 */
struct ip6_ctx {
	struct in6_addr addr;
	struct in6_addr addr_ll;
	struct in6_addr addr_seen;
	struct in6_addr addr_ll_seen;
	struct in6_addr gw;
	struct in6_addr dns[MAXNS + 1];
	struct in6_addr dns_match;
	struct in6_addr dns_host;
	struct in6_addr dns_redirect;

	struct in6_addr addr_out;
	char ifname_out[IFNAMSIZ];
};

#include <netinet/if_ether.h>

/**
 * struct ctx - Execution context
 * @mode:		Operation mode, qemu/UNIX domain socket or namespace/tap
 * @debug:		Enable debug mode
 * @trace:		Enable tracing (extra debug) mode
 * @quiet:		Don't print informational messages
 * @foreground:		Run in foreground, don't log to stderr by default
 * @force_stderr:	Force logging to stderr
 * @nofile:		Maximum number of open files (ulimit -n)
 * @sock_path:		Path for UNIX domain socket
 * @pcap:		Path for packet capture file
 * @pid_file:		Path to PID file, empty string if not configured
 * @pasta_netns_fd:	File descriptor for network namespace in pasta mode
 * @no_netns_quit:	In pasta mode, don't exit if fs-bound namespace is gone
 * @netns_base:		Base name for fs-bound namespace, if any, in pasta mode
 * @netns_dir:		Directory of fs-bound namespace, if any, in pasta mode
 * @proc_net_tcp:	Stored handles for /proc/net/tcp{,6} in init and ns
 * @proc_net_udp:	Stored handles for /proc/net/udp{,6} in init and ns
 * @epollfd:		File descriptor for epoll instance
 * @fd_tap_listen:	File descriptor for listening AF_UNIX socket, if any
 * @fd_tap:		AF_UNIX socket, tuntap device, or pre-opened socket
 * @mac:		Host MAC address
 * @mac_guest:		MAC address of guest or namespace, seen or configured
 * @ifi4:		Index of template interface for IPv4, 0 if IPv4 disabled
 * @ip:			IPv4 configuration
 * @dns_search:		DNS search list
 * @ifi6:		Index of template interface for IPv6, 0 if IPv6 disabled
 * @ip6:		IPv6 configuration
 * @pasta_ifn:		Name of namespace interface for pasta
 * @pasta_ifn:		Index of namespace interface for pasta
 * @pasta_conf_ns:	Configure namespace interface after creating it
 * @no_tcp:		Disable TCP operation
 * @tcp:		Context for TCP protocol handler
 * @no_tcp:		Disable UDP operation
 * @udp:		Context for UDP protocol handler
 * @no_icmp:		Disable ICMP operation
 * @icmp:		Context for ICMP protocol handler
 * @mtu:		MTU passed via DHCP/NDP
 * @no_dns:		Do not source/use DNS servers for any purpose
 * @no_dns_search:	Do not source/use domain search lists for any purpose
 * @no_dhcp_dns:	Do not assign any DNS server via DHCP/DHCPv6/NDP
 * @no_dhcp_dns_search:	Do not assign any DNS domain search via DHCP/DHCPv6/NDP
 * @no_dhcp:		Disable DHCP server
 * @no_dhcpv6:		Disable DHCPv6 server
 * @no_ndp:		Disable NDP handler altogether
 * @no_ra:		Disable router advertisements
 * @no_map_gw:		Don't map connections, untracked UDP to gateway to host
 * @low_wmem:		Low probed net.core.wmem_max
 * @low_rmem:		Low probed net.core.rmem_max
 */
struct ctx {
	enum passt_modes mode;
	int debug;
	int trace;
	int quiet;
	int foreground;
	int force_stderr;
	int nofile;
	char sock_path[UNIX_PATH_MAX];
	char pcap[PATH_MAX];
	char pid_file[PATH_MAX];
	int one_off;

	int pasta_netns_fd;

	int no_netns_quit;
	char netns_base[PATH_MAX];
	char netns_dir[PATH_MAX];

	int proc_net_tcp[IP_VERSIONS][2];
	int proc_net_udp[IP_VERSIONS][2];

	int epollfd;
	int fd_tap_listen;
	int fd_tap;
	unsigned char mac[ETH_ALEN];
	unsigned char mac_guest[ETH_ALEN];

	unsigned int ifi4;
	struct ip4_ctx ip4;

	struct fqdn dns_search[MAXDNSRCH];

	unsigned int ifi6;
	struct ip6_ctx ip6;

	char pasta_ifn[IF_NAMESIZE];
	unsigned int pasta_ifi;
	int pasta_conf_ns;

	int no_tcp;
	struct tcp_ctx tcp;
	int no_udp;
	struct udp_ctx udp;
	int no_icmp;
	struct icmp_ctx icmp;

	int mtu;
	int no_dns;
	int no_dns_search;
	int no_dhcp_dns;
	int no_dhcp_dns_search;
	int no_dhcp;
	int no_dhcpv6;
	int no_ndp;
	int no_ra;
	int no_map_gw;

	int low_wmem;
	int low_rmem;

	pid_t keep_child_pid;
	struct proxy_conf proxy;
};

void proto_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s,
			 const struct in_addr *ip_da);

#endif /* PASST_H */

/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

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

#include "icmp.h"
#include "tcp.h"
#include "udp.h"

/**
 * union epoll_ref - Breakdown of reference for epoll socket bookkeeping
 * @proto:	IP protocol number
 * @s:		Socket number (implies 2^24 limit on number of descriptors)
 * @tcp:	TCP-specific reference part
 * @udp:	UDP-specific reference part
 * @icmp:	ICMP-specific reference part
 * @data:	Data handled by protocol handlers
 * @u64:	Opaque reference for epoll_ctl() and epoll_wait()
 */
union epoll_ref {
	struct {
		uint32_t	proto:8,
				s:24;
		union {
			union tcp_epoll_ref tcp;
			union udp_epoll_ref udp;
			union icmp_epoll_ref icmp;
			uint32_t data;
		};
	};
	uint64_t u64;
};

#define TAP_BUF_BYTES							\
	ROUND_DOWN(((ETH_MAX_MTU + sizeof(uint32_t)) * 256), PAGE_SIZE)
#define TAP_BUF_FILL		(TAP_BUF_BYTES - ETH_MAX_MTU - sizeof(uint32_t))
#define TAP_MSGS							\
	DIV_ROUND_UP(TAP_BUF_BYTES, ETH_ZLEN - 2 * ETH_ALEN + sizeof(uint32_t))

#define PKT_BUF_BYTES		MAX(TAP_BUF_BYTES, 0)
extern char pkt_buf		[PKT_BUF_BYTES];

extern char *ip_proto_str[];
#define IP_PROTO_STR(n)							\
	(((n) <= IPPROTO_SCTP && ip_proto_str[(n)]) ? ip_proto_str[(n)] : "?")

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
 * struct ctx - Execution context
 * @mode:		Operation mode, qemu/UNIX domain socket or namespace/tap
 * @debug:		Enable debug mode
 * @quiet:		Don't print informational messages
 * @foreground:		Run in foreground, don't log to stderr by default
 * @stderr:		Force logging to stderr
 * @sock_path:		Path for UNIX domain socket
 * @pcap:		Path for packet capture file
 * @pid_file:		Path to PID file, empty string if not configured
 * @pasta_netns_fd:	File descriptor for network namespace in pasta mode
 * @pasta_userns_fd:	File descriptor for user namespace in pasta mode
 * @netns_only:		In pasta mode, don't join or create a user namespace
 * @epollfd:		File descriptor for epoll instance
 * @fd_tap_listen:	File descriptor for listening AF_UNIX socket, if any
 * @fd_tap:		File descriptor for AF_UNIX socket or tuntap device
 * @mac:		Host MAC address
 * @mac_guest:		MAC address of guest or namespace, seen or configured
 * @v4:			Enable IPv4 transport
 * @addr4:		IPv4 address for external, routable interface
 * @addr4_seen:		Latest IPv4 address seen as source from tap
 * @mask4:		IPv4 netmask, network order
 * @gw4:		Default IPv4 gateway, network order
 * @dns4:		IPv4 DNS addresses, zero-terminated, network order
 * @dns_search:		DNS search list
 * @v6:			Enable IPv6 transport
 * @addr6:		IPv6 address for external, routable interface
 * @addr6_ll:		Link-local IPv6 address on external, routable interface
 * @addr6_seen:		Latest IPv6 global/site address seen as source from tap
 * @addr6_ll_seen:	Latest IPv6 link-local address seen as source from tap
 * @gw6:		Default IPv6 gateway
 * @dns4:		IPv4 DNS addresses, zero-terminated
 * @ifi:		Index of routable interface
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
 * @no_dns:		Do not assign any DNS server via DHCP/DHCPv6/NDP
 * @no_dns_search:	Do not assign any DNS domain search via DHCP/DHCPv6/NDP
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
	int quiet;
	int foreground;
	int stderr;
	char sock_path[UNIX_PATH_MAX];
	char pcap[PATH_MAX];
	char pid_file[PATH_MAX];

	int pasta_netns_fd;
	int pasta_userns_fd;
	int netns_only;

	int epollfd;
	int fd_tap_listen;
	int fd_tap;
	unsigned char mac[ETH_ALEN];
	unsigned char mac_guest[ETH_ALEN];

	int v4;
	uint32_t addr4;
	uint32_t addr4_seen;
	uint32_t mask4;
	uint32_t gw4;
	uint32_t dns4[MAXNS + 1];

	struct fqdn dns_search[MAXDNSRCH];

	int v6;
	struct in6_addr addr6;
	struct in6_addr addr6_ll;
	struct in6_addr addr6_seen;
	struct in6_addr addr6_ll_seen;
	struct in6_addr gw6;
	struct in6_addr dns6[MAXNS + 1];

	unsigned int ifi;
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
	int no_dhcp;
	int no_dhcpv6;
	int no_ndp;
	int no_ra;
	int no_map_gw;

	int low_wmem;
	int low_rmem;
};

void proto_update_l2_buf(unsigned char *eth_d, unsigned char *eth_s,
			 uint32_t *ip_da);

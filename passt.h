#define UNIX_SOCK_PATH	"/tmp/passt.socket"

/**
 * struct tap_msg - Generic message descriptor for arrays of messages
 * @start:	Pointer to message start
 * @l4_start:	Pointer to L4 header
 * @len:	Message length, with L2 headers
 * @l4_len:	Message length, with L4 headers
 */
struct tap_msg {
	char *start;
	char *l4h;
	size_t len;
	size_t l4_len;
};

#define SOCK_BUF_BYTES		(ETH_MAX_MTU * 4)

#include "icmp.h"
#include "tcp.h"
#include "udp.h"

/**
 * struct ctx - Execution context
 * @epollfd:		file descriptor for epoll instance
 * @fd_unix:		AF_UNIX socket for tap file descriptor
 * @v4:			Enable IPv4 transport
 * @mac:		Host MAC address
 * @mac_guest:		Guest MAC address
 * @addr4:		IPv4 address for external, routable interface
 * @addr4_seen:		Latest IPv4 address seen as source from tap
 * @mask4:		IPv4 netmask, network order
 * @gw4:		Default IPv4 gateway, network order
 * @dns4:		IPv4 DNS address, network order
 * @v6:			Enable IPv6 transport
 * @addr6:		IPv6 address for external, routable interface
 * @addr6_seen:		Latest IPv6 global/site address seen as source from tap
 * @addr6_ll_seen:	Latest IPv6 link-local address seen as source from tap
 * @gw6:		Default IPv6 gateway
 * @dns4:		IPv6 DNS address
 * @ifn:		Name of routable interface
 */
struct ctx {
	int epollfd;
	int fd_unix;
	unsigned char mac[ETH_ALEN];
	unsigned char mac_guest[ETH_ALEN];

	int v4;
	uint32_t addr4;
	uint32_t addr4_seen;
	uint32_t mask4;
	uint32_t gw4;
	uint32_t dns4;

	int v6;
	struct in6_addr addr6;
	struct in6_addr addr6_seen;
	struct in6_addr addr6_ll_seen;
	struct in6_addr gw6;
	struct in6_addr dns6;

	char ifn[IF_NAMESIZE];

	struct icmp_ctx icmp;
	struct tcp_ctx tcp;
	struct udp_ctx udp;
};

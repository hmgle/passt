#define UNIX_SOCK_MAX		100
#define UNIX_SOCK_PATH		"/tmp/passt_%i.socket"

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
	uint16_t len;
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

#define TAP_BUF_BYTES		(ETH_MAX_MTU * 128)
#define TAP_BUF_FILL		(TAP_BUF_BYTES - ETH_MAX_MTU - sizeof(uint32_t))
#define TAP_MSGS		(TAP_BUF_BYTES / sizeof(struct ethhdr) + 1)

#define PKT_BUF_BYTES		MAX(TAP_BUF_BYTES, 0)
extern char pkt_buf		[PKT_BUF_BYTES];

#ifdef DEBUG
extern char *ip_proto_str[];
#define IP_PROTO_STR(n)							\
	(((n) <= IPPROTO_SCTP && ip_proto_str[(n)]) ? ip_proto_str[(n)] : "?")
#endif

#include <resolv.h>	/* For MAXNS below */

/**
 * struct fqdn - Representation of fully-qualified domain name
 * @n:		Domain name string
 */
struct fqdn {
	char n[NS_MAXDNAME];
};

#include <net/if.h>

enum passt_modes {
	MODE_PASST,
	MODE_PASTA,
};

/**
 * struct ctx - Execution context
 * @mode:		Operation mode, qemu/UNIX domain socket or namespace/tap
 * @pasta_pid:		Target PID of namespace for pasta mode
 * @epollfd:		File descriptor for epoll instance
 * @fd_tap_listen:	File descriptor for listening AF_UNIX socket, if any
 * @fd_tap:		File descriptor for AF_UNIX socket or tuntap device
 * @mac:		Host MAC address
 * @mac_guest:		Guest MAC address
 * @v4:			Enable IPv4 transport
 * @addr4:		IPv4 address for external, routable interface
 * @addr4_seen:		Latest IPv4 address seen as source from tap
 * @mask4:		IPv4 netmask, network order
 * @gw4:		Default IPv4 gateway, network order
 * @dns4:		IPv4 DNS addresses, zero-terminated, network order
 * @dns_search:		DNS search list
 * @v6:			Enable IPv6 transport
 * @addr6:		IPv6 address for external, routable interface
 * @addr6_seen:		Latest IPv6 global/site address seen as source from tap
 * @addr6_ll_seen:	Latest IPv6 link-local address seen as source from tap
 * @gw6:		Default IPv6 gateway
 * @dns4:		IPv4 DNS addresses, zero-terminated
 * @ifn:		Name of routable interface
 * @tcp:		Context for TCP protocol handler
 * @udp:		Context for UDP protocol handler
 * @icmp:		Context for ICMP protocol handler
 */
struct ctx {
	enum passt_modes mode;
	int pasta_pid;

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
	struct in6_addr addr6_seen;
	struct in6_addr addr6_ll_seen;
	struct in6_addr gw6;
	struct in6_addr dns6[MAXNS + 1];

	char ifn[IF_NAMESIZE];

	struct tcp_ctx tcp;
	struct udp_ctx udp;
	struct icmp_ctx icmp;
};

void proto_update_l2_buf(unsigned char *eth_d, unsigned char *eth_s,
			 uint32_t *ip_da);

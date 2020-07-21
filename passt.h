#define CT_SIZE		4096
#define UNIX_SOCK_PATH	"/tmp/passt.socket"

/**
 * struct ct4 - IPv4 connection tracking entry
 * @p:		IANA protocol number
 * @sa:		Source address (as seen from tap interface)
 * @da:		Destination address
 * @sp:		Source port, network order
 * @dp:		Destination port, network order
 * @hd:		Destination MAC address
 * @hs:		Source MAC address
 * @fd:		File descriptor for corresponding AF_INET socket
 */
struct ct4 {
	uint8_t p;
	uint32_t sa;
	uint32_t da;
	uint16_t sp;
	uint16_t dp;
	unsigned char hd[ETH_ALEN];
	unsigned char hs[ETH_ALEN];
	int fd;
};

/**
 * struct ct6 - IPv6 connection tracking entry
 * @p:		IANA protocol number
 * @sa:		Source address (as seen from tap interface)
 * @da:		Destination address
 * @sp:		Source port, network order
 * @dp:		Destination port, network order
 * @hd:		Destination MAC address
 * @hs:		Source MAC address
 * @fd:		File descriptor for corresponding AF_INET6 socket
 */
struct ct6 {
	uint8_t p;
	struct in6_addr sa;
	struct in6_addr da;
	uint16_t sp;
	uint16_t dp;
	unsigned char hd[ETH_ALEN];
	unsigned char hs[ETH_ALEN];
	int fd;
};

/**
 * struct ctx - Execution context
 * @epollfd:	file descriptor for epoll instance
 * @fd_unix:	AF_UNIX socket for tap file descriptor
 * @map4:	Connection tracking table
 * @v4:		Enable IPv4 transport
 * @addr4:	IPv4 address for external, routable interface
 * @mask4:	IPv4 netmask, network order
 * @gw4:	Default IPv4 gateway, network order
 * @dns4:	IPv4 DNS address, network order
 * @v6:		Enable IPv6 transport
 * @addr6:	IPv6 address for external, routable interface
 * @gw6:	Default IPv6 gateway
 * @dns4:	IPv6 DNS address
 * @ifn:	Name of routable interface
 */
struct ctx {
	int epollfd;
	int fd_unix;
	struct ct4 map4[CT_SIZE];
	struct ct6 map6[CT_SIZE];
	unsigned char mac[ETH_ALEN];

	int v4;
	unsigned long addr4;
	unsigned long mask4;
	unsigned long gw4;
	unsigned long dns4;

	int v6;
	struct in6_addr addr6;
	struct in6_addr gw6;
	struct in6_addr dns6;

	char ifn[IF_NAMESIZE];
};

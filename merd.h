#define CT_SIZE		4096
#define UNIX_SOCK_PATH	"/tmp/merd.socket"

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
 * struct ctx - Execution context
 * @epollfd:	file descriptor for epoll instance
 * @fd_unix:	AF_UNIX socket for tap file descriptor
 * @map4:	Connection tracking table
 * @addr4:	IPv4 address for external, routable interface
 * @mask4:	IPv4 netmask, network order
 * @gw4:	Default IPv4 gateway, network order
 * @dns4:	IPv4 DNS address, network order
 * @ifn:	Name of routable interface
 */
struct ctx {
	int epollfd;
	int fd_unix;
	struct ct4 map4[CT_SIZE];
	unsigned char mac[ETH_ALEN];
	unsigned long addr4;
	unsigned long mask4;
	unsigned long gw4;
	unsigned long dns4;
	char ifn[IF_NAMESIZE];
};

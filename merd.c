/* MERD - MacVTap Egress and Routing Daemon
 *
 * merd.c - Daemon implementation
 *
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * License: GPLv2
 *
 * Grab Ethernet frames via AF_UNIX socket, build AF_INET sockets for each
 * 5-tuple from ICMP, TCP, UDP packets, perform connection tracking and forward
 * them with destination address NAT. Forward packets received on sockets back
 * to the UNIX domain socket (typically, a tap file descriptor from qemu).
 *
 * TODO:
 * - steal packets from AF_INET sockets (using eBPF/XDP, or a new socket
 *   option): currently, incoming packets are also handled by in-kernel protocol
 *   handlers, so every incoming untracked TCP packet gets a RST. Workaround:
 *	iptables -A OUTPUT -m state --state INVALID,NEW,ESTABLISHED \
 *				-p tcp --tcp-flags RST RST -j DROP
 * - and use XDP sockmap on top of that to improve performance
 * - add IPv6 support. Current workaround on the namespace or machine on the
 *   tap side:
 *	echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
 * - reserve and translate ports
 * - aging and timeout/RST bookkeeping for connection tracking entries
 */

#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_link.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <linux/ip.h>

#include "merd.h"

#define EPOLL_EVENTS	10
#define CT_SIZE		4096

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
 * @ext_addr4:	IPv4 address for external, routable interface
 * @fd_unix:	AF_UNIX socket for tap file descriptor
 * @map4:	Connection tracking table
 */
struct ctx {
	int epollfd;
	unsigned long ext_addr4;
	int fd_unix;
	struct ct4 map4[CT_SIZE];
};

/**
 * sock_unix() - Create and bind AF_UNIX socket, add to epoll list
 *
 * Return: newly created socket, doesn't return on error
 */
static int sock_unix(void)
{
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = UNIX_SOCK_PATH,
	};
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("UNIX socket");
		exit(EXIT_FAILURE);
	}

	unlink(UNIX_SOCK_PATH);
	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("UNIX socket bind");
		exit(EXIT_FAILURE);
	}
	return fd;
}

/**
 * getaddrs_ext() - Fetch IP addresses of external routable interface
 * @c:		Execution context
 * @ifn:	Name of external interface
 */
static void getaddrs_ext(struct ctx *c, const char *ifn)
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_in *in_addr;

		if (strcmp(ifa->ifa_name, ifn))
			continue;

		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;

		in_addr = (struct sockaddr_in *)ifa->ifa_addr;
		c->ext_addr4 = in_addr->sin_addr.s_addr;
		freeifaddrs(ifaddr);
		return;
	}

	fprintf(stderr, "Couldn't get IPv4 address for external interface\n");
	freeifaddrs(ifaddr);
	exit(EXIT_FAILURE);
}

/**
 * sock4_l4() - Create and bind AF_INET socket for given L4, add to epoll list
 * @c:		Execution context
 * @proto:	Protocol number, network order
 * @port:	L4 port, network order
 *
 * Return: newly created socket, -1 on error
 */
static int sock4_l4(struct ctx *c, uint16_t proto, uint16_t port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = port,
		.sin_addr = { .s_addr = c->ext_addr4 },
	};
	struct epoll_event ev = { 0 };
	int fd;

	fd = socket(AF_INET, SOCK_RAW, proto);
	if (fd < 0) {
		perror("L4 socket");
		return -1;
	}

	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		perror("epoll_ctl");
		return -1;
	}

	return fd;
}

/**
 * usage() - Print usage and exit
 * @name:	Executable name
 */
void usage(const char *name)
{
	fprintf(stderr, "Usage: %s IF_EXT\n", name);

	exit(EXIT_FAILURE);
}

/**
 * lookup4() - Look up socket entry from tap-sourced packet, create if missing
 * @c:		Execution context
 * @in:		Packet buffer, L2 headers
 *
 * Return: -1 for unsupported or too many sockets, matching socket otherwise
 */
static int lookup4(struct ctx *c, const char *in)
{
	char buf_s[BUFSIZ], buf_d[BUFSIZ];
	struct ct4 *ct = c->map4;
	struct tcphdr *th;
	struct iphdr *iph;
	struct ethhdr *eh;
	int i;

	eh = (struct ethhdr *)in;
	iph = (struct iphdr *)(in + ETH_HLEN);
	th = (struct tcphdr *)(iph + 1);

	switch (iph->protocol) {
	case IPPROTO_ICMP:
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;
	default:
		return -1;
	}

	for (i = 0; i < CT_SIZE; i++) {
		if (ct[i].p == iph->protocol &&
		    ct[i].sa == iph->saddr && ct[i].da == iph->daddr &&
		    (ct[i].p == IPPROTO_ICMP ||
		     (ct[i].sp == th->source && ct[i].dp == th->dest)) &&
		    !memcmp(ct[i].hd, eh->h_dest, ETH_ALEN) &&
		    !memcmp(ct[i].hs, eh->h_source, ETH_ALEN))
			return ct[i].fd;
	}

	for (i = 0; i < CT_SIZE && ct[i].p; i++);

	if (i == CT_SIZE) {
		fprintf(stderr, "\nToo many sockets, aborting ");
	} else {
		ct[i].fd = sock4_l4(c, iph->protocol, th->source);

		fprintf(stderr, "\n(socket %i) New ", ct[i].fd);
		ct[i].p = iph->protocol;
		ct[i].sa = iph->saddr;
		ct[i].da = iph->daddr;
		if (iph->protocol != IPPROTO_ICMP) {
			ct[i].sp = th->source;
			ct[i].dp = th->dest;
		}
		memcpy(&ct[i].hd, eh->h_dest, ETH_ALEN);
		memcpy(&ct[i].hs, eh->h_source, ETH_ALEN);
	}

	if (iph->protocol == IPPROTO_ICMP) {
		fprintf(stderr, "icmp connection\n\tfrom %s to %s\n\n",
			inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
			inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)));
	} else {
		fprintf(stderr, "%s connection\n\tfrom %s:%i to %s:%i\n\n",
			getprotobynumber(iph->protocol)->p_name,
			inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
			ntohs(th->source),
			inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)),
			ntohs(th->dest));
	}

	return (i == CT_SIZE) ? -1 : ct[i].fd;
}

/**
 * lookup4_r4() - Reverse look up connection tracking entry from incoming packet
 * @ct:		Connection tracking table
 * @in:		Packet buffer, L3 headers
 *
 * Return: matching entry if any, NULL otherwise
 */
struct ct4 *lookup_r4(struct ct4 *ct, const char *in)
{
	struct tcphdr *th;
	struct iphdr *iph;
	int i;

	iph = (struct iphdr *)in;
	th = (struct tcphdr *)(iph + 1);

	for (i = 0; i < CT_SIZE; i++) {
		if (iph->protocol == ct[i].p &&
		    iph->saddr == ct[i].da &&
		    (iph->protocol == IPPROTO_ICMP ||
		     (th->source == ct[i].dp && th->dest == ct[i].sp)))
			return &ct[i];
	}

	return NULL;
}

/**
 * nat4_out() - Perform outgoing IPv4 address translation
 * @addr:	Source address to be used
 * @in:		Packet buffer, L3 headers
 */
static void nat4_out(unsigned long addr, const char *in)
{
	struct iphdr *iph = (struct iphdr *)in;

	iph->saddr = addr;
}

/**
 * nat4_in() - Perform incoming IPv4 address translation
 * @addr:	Original destination address to be used
 * @in:		Packet buffer, L3 headers
 */
static void nat_in(unsigned long addr, const char *in)
{
	struct iphdr *iph = (struct iphdr *)in;

	iph->daddr = addr;
}

/**
 * csum_fold() - Fold long sum for IP and TCP checksum
 * @sum:	Original long sum
 *
 * Return: 16-bit folded sum
 */
static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

/**
 * csum_ipv4() - Calculate IPv4 checksum
 * @buf:	Packet buffer, L3 headers
 * @len:	Total L3 packet length
 *
 * Return: 16-bit IPv4-style checksum
 */
static uint16_t csum_ip4(void *buf, size_t len)
{
	uint32_t sum = 0;
	uint16_t *p = buf;
	size_t len1 = len / 2;
	size_t off;

	for (off = 0; off < len1; off++, p++)
		sum += *p;

	if (len % 2)
		sum += *p & 0xff;

	return ~csum_fold(sum);
}

/**
 * csum_ipv4() - Calculate TCP checksum for IPv4 and set in place
 * @in:		Packet buffer, L3 headers
 */
static void csum_tcp4(uint16_t *in)
{
	struct iphdr *iph = (struct iphdr *)in;
	struct tcphdr *th;
	uint16_t tcp_len;
	uint32_t sum = 0;

	tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2);
	th = (struct tcphdr *)(iph + 1);
	in = (uint16_t *)th;

	sum += (iph->saddr >> 16) & 0xffff;
	sum += iph->saddr & 0xffff;
	sum += (iph->daddr >> 16) & 0xffff;
	sum += iph->daddr & 0xffff;

	sum += htons(IPPROTO_TCP);
	sum += htons(tcp_len);

	th->check = 0;
	while (tcp_len > 1) {
		sum += *in++;
		tcp_len -= 2;
	}

	if (tcp_len > 0) {
		sum += *in & htons(0xff00);
	}

	th->check = (uint16_t)~csum_fold(sum);
}

/**
 * tap4_handler() - Packet handler for tap file descriptor
 * @c:		Execution context
 * @len:	Total L2 packet length
 * @in:		Packet buffer, L2 headers
 */
static void tap4_handler(struct ctx *c, int len, char *in)
{
	struct iphdr *iph = (struct iphdr *)(in + ETH_HLEN);
	struct tcphdr *th = (struct tcphdr *)(iph + 1);
	struct udphdr *uh = (struct udphdr *)(iph + 1);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = th->dest,
		.sin_addr = { .s_addr = iph->daddr },
	};
	char buf_s[BUFSIZ], buf_d[BUFSIZ];
	int fd;

	fd = lookup4(c, in);
	if (fd == -1)
		return;

	if (iph->protocol == IPPROTO_ICMP) {
		fprintf(stderr, "icmp from tap: %s -> %s (socket %i)\n",
			inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
			inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)),
			fd);
	} else {
		fprintf(stderr, "%s from tap: %s:%i -> %s:%i (socket %i)\n",
			getprotobynumber(iph->protocol)->p_name,
			inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
			ntohs(th->source),
			inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)),
			ntohs(th->dest),
			fd);
	}

	nat4_out(c->ext_addr4, in + ETH_HLEN);

	switch (iph->protocol) {
	case IPPROTO_TCP:
		csum_tcp4((uint16_t *)(in + ETH_HLEN));
		break;
	case IPPROTO_UDP:
		uh->check = 0;
		break;
	case IPPROTO_ICMP:
		break;
	default:
		return;
	}

	if (sendto(fd, in + sizeof(struct ethhdr) + sizeof(struct iphdr),
		   len - sizeof(struct ethhdr) - 4 * iph->ihl, 0,
		   (struct sockaddr *)&addr, sizeof(addr)) < 0)
		perror("sendto");

}

/**
 * tap4_handler() - Packet handler for external routable interface
 * @c:		Execution context
 * @len:	Total L3 packet length
 * @in:		Packet buffer, L3 headers
 */
static void ext4_handler(struct ctx *c, int len, char *in)
{
	struct iphdr *iph = (struct iphdr *)in;
	struct tcphdr *th = (struct tcphdr *)(iph + 1);
	char buf_s[BUFSIZ], buf_d[BUFSIZ];
	struct ethhdr *eh;
	struct ct4 *entry;
	char buf[1 << 16];

	entry = lookup_r4(c->map4, in);
	if (!entry)
		return;

	nat_in(entry->sa, in);

	iph->check = 0;
	iph->check = csum_ip4(iph, 4 * iph->ihl);

	if (iph->protocol == IPPROTO_TCP)
		csum_tcp4((uint16_t *)in);
	else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *uh = (struct udphdr *)(iph + 1);
		uh->check = 0;
	}

	eh = (struct ethhdr *)buf;
	memcpy(eh->h_dest, entry->hs, ETH_ALEN);
	memcpy(eh->h_source, entry->hd, ETH_ALEN);
	eh->h_proto = ntohs(ETH_P_IP);

	memcpy(buf + sizeof(struct ethhdr), in, len);

	if (iph->protocol == IPPROTO_ICMP) {
		fprintf(stderr, "icmp (socket %i) to tap: %s -> %s\n",
			entry->fd,
			inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
			inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)));
	} else {
		fprintf(stderr, "%s (socket %i) to tap: %s:%i -> %s:%i\n",
			getprotobynumber(iph->protocol)->p_name,
			entry->fd,
			inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
			ntohs(th->source),
			inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)),
			ntohs(th->dest));
	}

	if (send(c->fd_unix, buf, len + sizeof(struct ethhdr), 0) < 0)
		perror("send");
}

/**
 * main() - Entry point and main loop
 * @argc:	Argument count
 * @argv:	Interface names
 *
 * Return: 0 once interrupted, non-zero on failure
 */
int main(int argc, char **argv)
{
	struct epoll_event events[EPOLL_EVENTS];
	struct epoll_event ev = { 0 };
	struct ctx c = { 0 };
	const char *if_ext;
	char buf[1 << 16];
	int nfds, i, len;
	int fd_unix;

	if (argc != 2)
		usage(argv[0]);

	if_ext = argv[1];
	getaddrs_ext(&c, if_ext);

	c.epollfd = epoll_create1(0);
	if (c.epollfd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	fd_unix = sock_unix();
listen:
	listen(fd_unix, 1);
	fprintf(stderr,
		"You can now start qrap:\n\t"
		"./qrap 42 kvm ... -net tap,fd=42 -net nic,model=virtio ...\n");

	c.fd_unix = accept(fd_unix, NULL, NULL);
	ev.events = EPOLLIN;
	ev.data.fd = c.fd_unix;
	epoll_ctl(c.epollfd, EPOLL_CTL_ADD, c.fd_unix, &ev);

loop:
	nfds = epoll_wait(c.epollfd, events, EPOLL_EVENTS, -1);
	if (nfds == -1) {
		perror("epoll_wait");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < nfds; i++) {
		len = recv(events[i].data.fd, buf, sizeof(buf), MSG_DONTWAIT);

		if (events[i].data.fd == c.fd_unix && len <= 0) {
			epoll_ctl(c.epollfd, EPOLL_CTL_DEL, c.fd_unix, &ev);
			close(c.fd_unix);
			goto listen;
		}

		if (len == 0)
			continue;

		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			goto out;
		}

		if (events[i].data.fd == c.fd_unix)
			tap4_handler(&c, len, buf);
		else
			ext4_handler(&c, len, buf);
	}

	goto loop;

out:
	return 0;
}

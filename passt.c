/* PASST - Plug A Simple Socket Transport
 *
 * passt.c - Daemon implementation
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
#include <sys/ioctl.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "passt.h"
#include "arp.h"
#include "dhcp.h"
#include "util.h"

#define EPOLL_EVENTS	10

/**
 * sock_unix() - Create and bind AF_UNIX socket, add to epoll list
 *
 * Return: newly created socket, doesn't return on error
 */
static int sock_unix(void)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = UNIX_SOCK_PATH,
	};

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
 * struct nl_request - Netlink request filled and sent by get_routes()
 * @nlh:	Netlink message header
 * @rtm:	Routing Netlink message
 */
struct nl_request {
	struct nlmsghdr nlh;
	struct rtmsg rtm;
};

/**
 * get_routes() - Get default route and fill in routable interface name
 * @c:		Execution context
 */
static void get_routes(struct ctx *c)
{
	struct nl_request req = {
		.nlh.nlmsg_type = RTM_GETROUTE,
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_EXCL,
		.nlh.nlmsg_len = sizeof(struct nl_request),
		.nlh.nlmsg_seq = 1,
		.rtm.rtm_family = AF_INET,
		.rtm.rtm_table = RT_TABLE_MAIN,
		.rtm.rtm_scope = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type = RTN_UNICAST,
	};
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
	};
	int s, n, na, found = 0;
	struct nlmsghdr *nlh;
	struct rtattr *rta;
	struct rtmsg *rtm;
	char buf[BUFSIZ];

	s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("netlink socket");
		goto out;
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("netlink bind");
		goto out;
	}

	if (send(s, &req, sizeof(req), 0) < 0) {
		perror("netlink send");
		goto out;
	}

	n = recv(s, &buf, sizeof(buf), 0);
	if (n < 0) {
		perror("netlink recv");
		goto out;
	}

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_DONE)
		goto out;

	for ( ; NLMSG_OK(nlh, n) && found < 2; NLMSG_NEXT(nlh, n)) {
		rtm = (struct rtmsg *)NLMSG_DATA(nlh);

		if (rtm->rtm_dst_len)
			continue;

		rta = (struct rtattr *)RTM_RTA(rtm);
		na = RTM_PAYLOAD(nlh);
		for ( ; RTA_OK(rta, na) && found < 2; rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type == RTA_GATEWAY) {
				memcpy(&c->gw4, RTA_DATA(rta), sizeof(c->gw4));
				found++;
			}

			if (rta->rta_type == RTA_OIF) {
				if_indextoname(*(unsigned *)RTA_DATA(rta),
					       c->ifn);
				found++;
			}
		}
	}

out:
	close(s);

	if (found < 2) {
		fprintf(stderr, "No routing information\n");
		exit(EXIT_FAILURE);
	}
}

/**
 * get_addrs() - Fetch MAC, IP addresses, masks of external routable interface
 * @c:		Execution context
 */
static void get_addrs(struct ctx *c)
{
	struct ifreq ifr = {
		.ifr_addr.sa_family = AF_INET,
	};
	struct ifaddrs *ifaddr, *ifa;
	int s;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		goto out;
	}

	for (ifa = ifaddr; ifa && !c->addr4; ifa = ifa->ifa_next) {
		struct sockaddr_in *in_addr;

		if (strcmp(ifa->ifa_name, c->ifn))
			continue;

		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;

		in_addr = (struct sockaddr_in *)ifa->ifa_addr;
		c->addr4 = in_addr->sin_addr.s_addr;
		in_addr = (struct sockaddr_in *)ifa->ifa_netmask;
		c->mask4 = in_addr->sin_addr.s_addr;
	}

	freeifaddrs(ifaddr);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket SIOCGIFHWADDR");
		goto out;
	}

	strncpy(ifr.ifr_name, c->ifn, IF_NAMESIZE);
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
		perror("SIOCGIFHWADDR");
		goto out;
	}

	close(s);
	memcpy(c->mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return;
out:
	fprintf(stderr, "Couldn't get addresses for routable interface\n");
	exit(EXIT_FAILURE);
}

/**
 * get_dns() - Get nameserver addresses from local /etc/resolv.conf
 * @c:		Execution context
 */
static void get_dns(struct ctx *c)
{
	char buf[BUFSIZ], *p, *nl;
	int dns4 = 0;
	FILE *r;

	r = fopen("/etc/resolv.conf", "r");
	while (fgets(buf, BUFSIZ, r) && !dns4) {
		if (!strstr(buf, "nameserver "))
			continue;
		p = strrchr(buf, ' ');
		nl = strchr(buf, '\n');
		if (nl)
			*nl = 0;
		if (p && inet_pton(AF_INET, p + 1, &c->dns4))
			dns4 = 1;
	}

	fclose(r);
	if (dns4)
		return;

	fprintf(stderr, "Couldn't get IPv4 nameserver address\n");
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
		.sin_addr = { .s_addr = c->addr4 },
	};
	struct epoll_event ev = { 0 };
	int fd;

	fd = socket(AF_INET, SOCK_RAW, proto);
	if (fd < 0) {
		perror("L4 socket");
		return -1;
	}

	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("L4 bind");
		close(fd);
		return -1;
	}

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		perror("L4 epoll_ctl");
		return -1;
	}

	return fd;
}

/**
 * lookup4() - Look up socket entry from tap-sourced packet, create if missing
 * @c:		Execution context
 * @eh:		Packet buffer, Ethernet header
 *
 * Return: -1 for unsupported or too many sockets, matching socket otherwise
 */
static int lookup4(struct ctx *c, const struct ethhdr *eh)
{
	struct iphdr *iph = (struct iphdr *)(eh + 1);
	struct tcphdr *th = (struct tcphdr *)((char *)iph + iph->ihl * 4);
	char buf_s[BUFSIZ], buf_d[BUFSIZ];
	struct ct4 *ct = c->map4;
	int i, one_icmp_fd = 0;

	if (iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_TCP &&
	    iph->protocol != IPPROTO_UDP)
		return -1;

	for (i = 0; i < CT_SIZE; i++) {
		if (ct[i].p == iph->protocol && ct[i].sa == iph->saddr &&
		    ((ct[i].p == IPPROTO_ICMP && ct[i].da == iph->daddr)
		     || ct[i].sp == th->source) &&
		    !memcmp(ct[i].hd, eh->h_dest, ETH_ALEN) &&
		    !memcmp(ct[i].hs, eh->h_source, ETH_ALEN)) {
			if (iph->protocol != IPPROTO_ICMP) {
				ct[i].da = iph->daddr;
				ct[i].dp = th->dest;
			}
			return ct[i].fd;
		}
	}

	for (i = 0; i < CT_SIZE && ct[i].p; i++) {
		if (iph->protocol == IPPROTO_ICMP)
			one_icmp_fd = ct[i].fd;
	}

	if (i == CT_SIZE) {
		fprintf(stderr, "\nToo many sockets, aborting ");
	} else {
		if (iph->protocol == IPPROTO_ICMP && one_icmp_fd)
			ct[i].fd = one_icmp_fd;
		else
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
 * @fd:		File descriptor that received the packet
 * @iph:	Packet buffer, IP header
 *
 * Return: matching entry if any, NULL otherwise
 */
struct ct4 *lookup_r4(struct ct4 *ct, int fd, struct iphdr *iph)
{
	struct tcphdr *th = (struct tcphdr *)((char *)iph + iph->ihl * 4);
	int i;

	for (i = 0; i < CT_SIZE; i++) {
		if (ct[i].fd == fd &&
		    iph->protocol == ct[i].p &&
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
 * @iph:	IP header
 */
static void nat4_out(unsigned long addr, struct iphdr *iph)
{
	iph->saddr = addr;
}

/**
 * nat4_in() - Perform incoming IPv4 address translation
 * @addr:	Original destination address to be used
 * @iph:	IP header
 */
static void nat_in(unsigned long addr, struct iphdr *iph)
{
	iph->daddr = addr;
}

/**
 * csum_ipv4() - Calculate TCP checksum for IPv4 and set in place
 * @iph:	Packet buffer, IP header
 */
static void csum_tcp4(struct iphdr *iph)
{
	struct tcphdr *th = (struct tcphdr *)((char *)iph + iph->ihl * 4);
	uint16_t tlen = ntohs(iph->tot_len) - iph->ihl * 4, *p = (uint16_t *)th;
	uint32_t sum = 0;

	sum += (iph->saddr >> 16) & 0xffff;
	sum += iph->saddr & 0xffff;
	sum += (iph->daddr >> 16) & 0xffff;
	sum += iph->daddr & 0xffff;

	sum += htons(IPPROTO_TCP);
	sum += htons(tlen);

	th->check = 0;
	while (tlen > 1) {
		sum += *p++;
		tlen -= 2;
	}

	if (tlen > 0) {
		sum += *p & htons(0xff00);
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
	struct ethhdr *eh = (struct ethhdr *)in;
	struct iphdr *iph = (struct iphdr *)(eh + 1);
	struct tcphdr *th = (struct tcphdr *)((char *)iph + iph->ihl * 4);
	struct udphdr *uh = (struct udphdr *)th;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = th->dest,
		.sin_addr = { .s_addr = iph->daddr },
	};
	char buf_s[BUFSIZ], buf_d[BUFSIZ];
	int fd;

	if (arp(c, len, eh) || dhcp(c, len, eh))
		return;

	fd = lookup4(c, eh);
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

	if (iph->protocol == IPPROTO_TCP)
		csum_tcp4(iph);
	else if (iph->protocol == IPPROTO_UDP)
		uh->check = 0;
	else if (iph->protocol != IPPROTO_ICMP)
		return;

	nat4_out(c->addr4, iph);

	if (sendto(fd, (void *)th, len - sizeof(*eh) - iph->ihl * 4, 0,
		   (struct sockaddr *)&addr, sizeof(addr)) < 0)
		perror("sendto");

}

/**
 * ext4_handler() - Packet handler for external routable interface
 * @c:		Execution context
 * @fd:		File descriptor that received the packet
 * @len:	Total L3 packet length
 * @in:		Packet buffer, L3 headers
 */
static void ext4_handler(struct ctx *c, int fd, int len, char *in)
{
	struct iphdr *iph = (struct iphdr *)in;
	struct tcphdr *th = (struct tcphdr *)((char *)iph + iph->ihl * 4);
	struct udphdr *uh = (struct udphdr *)th;
	char buf_s[BUFSIZ], buf_d[BUFSIZ], buf[ETH_MAX_MTU];
	struct ethhdr *eh = (struct ethhdr *)buf;
	struct ct4 *entry;

	entry = lookup_r4(c->map4, fd, iph);
	if (!entry)
		return;

	nat_in(entry->sa, iph);

	iph->check = 0;
	iph->check = csum_ip4(iph, iph->ihl * 4);

	if (iph->protocol == IPPROTO_TCP)
		csum_tcp4(iph);
	else if (iph->protocol == IPPROTO_UDP)
		uh->check = 0;

	memcpy(eh->h_dest, entry->hs, ETH_ALEN);
	memcpy(eh->h_source, entry->hd, ETH_ALEN);
	eh->h_proto = ntohs(ETH_P_IP);

	memcpy(eh + 1, in, len);

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

	if (send(c->fd_unix, buf, len + sizeof(*eh), 0) < 0)
		perror("send");
}

/**
 * usage() - Print usage and exit
 * @name:	Executable name
 */
void usage(const char *name)
{
	fprintf(stderr, "Usage: %s\n", name);

	exit(EXIT_FAILURE);
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
	char buf4[4][sizeof("255.255.255.255")];
	struct epoll_event ev = { 0 };
	char buf[ETH_MAX_MTU];
	struct ctx c = { 0 };
	int nfds, i, len;
	int fd_unix;

	if (argc != 1)
		usage(argv[0]);

	get_routes(&c);
	get_addrs(&c);
	get_dns(&c);

	fprintf(stderr, "ARP:\n");
	fprintf(stderr, "\taddress: %02x:%02x:%02x:%02x:%02x:%02x from %s\n",
		c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5],
		c.ifn);
	fprintf(stderr, "DHCP:\n");
	fprintf(stderr, "\tassign: %s, mask: %s, router: %s, DNS: %s\n\n",
		inet_ntop(AF_INET, &c.addr4, buf4[0], sizeof(buf4[0])),
		inet_ntop(AF_INET, &c.mask4, buf4[1], sizeof(buf4[1])),
		inet_ntop(AF_INET, &c.gw4,   buf4[2], sizeof(buf4[2])),
		inet_ntop(AF_INET, &c.dns4,  buf4[3], sizeof(buf4[3])));

	c.epollfd = epoll_create1(0);
	if (c.epollfd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	fd_unix = sock_unix();
listen:
	listen(fd_unix, 1);
	c.fd_unix = accept(fd_unix, NULL, NULL);
	ev.events = EPOLLIN;
	ev.data.fd = c.fd_unix;
	epoll_ctl(c.epollfd, EPOLL_CTL_ADD, c.fd_unix, &ev);
	fprintf(stderr,
		"You can now start qrap:\n\t"
		"./qrap 42 kvm ... -net tap,fd=42 -net nic,model=virtio\n\n");

loop:
	nfds = epoll_wait(c.epollfd, events, EPOLL_EVENTS, -1);
	if (nfds == -1 && errno != EINTR) {
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

		if (len == 0 || (len < 0 && errno == EINTR))
			continue;

		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			goto out;
		}

		if (events[i].data.fd == c.fd_unix)
			tap4_handler(&c, len, buf);
		else
			ext4_handler(&c, events[i].data.fd, len, buf);
	}

	goto loop;

out:
	return 0;
}

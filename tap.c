// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tap.c - Functions to communicate with guest- or namespace-facing interface
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/un.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "arp.h"
#include "dhcp.h"
#include "ndp.h"
#include "dhcpv6.h"
#include "pcap.h"

/**
 * tap_send() - Send frame, with qemu socket header if needed
 * @c:		Execution context
 * @data:	Packet buffer
 * @len:	Total L2 packet length
 * @vnet_pre:	Buffer has four-byte headroom
 *
 * Return: return code from send() or write()
 */
int tap_send(struct ctx *c, void *data, size_t len, int vnet_pre)
{
	if (vnet_pre)
		pcap((char *)data + 4, len);
	else
		pcap(data, len);

	if (c->mode == MODE_PASST) {
		int flags = MSG_NOSIGNAL | MSG_DONTWAIT;

		if (vnet_pre) {
			*((uint32_t *)data) = htonl(len);
			len += 4;
		} else {
			uint32_t vnet_len = htonl(len);

			send(c->fd_tap, &vnet_len, 4, flags);
		}

		return send(c->fd_tap, data, len, flags);
	}

	return write(c->fd_tap, (char *)data + (vnet_pre ? 4 : 0), len);
}

/**
 * tap_ip_send() - Send IP packet, with L2 headers, calculating L3/L4 checksums
 * @c:		Execution context
 * @src:	IPv6 source address, IPv4-mapped for IPv4 sources
 * @proto:	L4 protocol number
 * @in:		Payload
 * @len:	L4 payload length
 * @flow:	Flow label for TCP over IPv6
 */
void tap_ip_send(struct ctx *c, struct in6_addr *src, uint8_t proto,
		 char *in, size_t len, uint32_t flow)
{
	char buf[USHRT_MAX];
	char *pkt = buf + 4;
	struct ethhdr *eh;

	eh = (struct ethhdr *)pkt;

	/* TODO: ARP table lookup */
	memcpy(eh->h_dest, c->mac_guest, ETH_ALEN);
	memcpy(eh->h_source, c->mac, ETH_ALEN);

	if (IN6_IS_ADDR_V4MAPPED(src)) {
		struct iphdr *iph = (struct iphdr *)(eh + 1);
		char *data = (char *)(iph + 1);

		eh->h_proto = ntohs(ETH_P_IP);

		iph->version = 4;
		iph->ihl = 5;
		iph->tos = 0;
		iph->tot_len = htons(len + 20);
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 255;
		iph->protocol = proto;
		iph->daddr = c->addr4_seen;
		memcpy(&iph->saddr, &src->s6_addr[12], 4);

		iph->check = 0;
		iph->check = csum_unaligned(iph, iph->ihl * 4, 0);

		memcpy(data, in, len);

		if (iph->protocol == IPPROTO_TCP) {
			csum_tcp4(iph);
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *uh = (struct udphdr *)(iph + 1);

			uh->check = 0;
		} else if (iph->protocol == IPPROTO_ICMP) {
			struct icmphdr *ih = (struct icmphdr *)(iph + 1);

			ih->checksum = 0;
			ih->checksum = csum_unaligned(ih, len, 0);
		}

		tap_send(c, buf, len + sizeof(*iph) + sizeof(*eh), 1);
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
		char *data = (char *)(ip6h + 1);

		eh->h_proto = ntohs(ETH_P_IPV6);

		memset(ip6h->flow_lbl, 0, 3);
		ip6h->payload_len = htons(len);
		ip6h->priority = 0;

		ip6h->saddr = *src;
		if (IN6_IS_ADDR_LINKLOCAL(src))
			ip6h->daddr = c->addr6_ll_seen;
		else
			ip6h->daddr = c->addr6_seen;

		memcpy(data, in, len);

		ip6h->hop_limit = proto;
		ip6h->version = 0;
		ip6h->nexthdr = 0;
		if (proto == IPPROTO_TCP) {
			struct tcphdr *th = (struct tcphdr *)(ip6h + 1);

			th->check = 0;
			th->check = csum_unaligned(ip6h, len + sizeof(*ip6h),
						   0);
		} else if (proto == IPPROTO_UDP) {
			struct udphdr *uh = (struct udphdr *)(ip6h + 1);

			uh->check = 0;
			uh->check = csum_unaligned(ip6h, len + sizeof(*ip6h),
						   0);
		} else if (proto == IPPROTO_ICMPV6) {
			struct icmp6hdr *ih = (struct icmp6hdr *)(ip6h + 1);

			ih->icmp6_cksum = 0;
			ih->icmp6_cksum = csum_unaligned(ip6h,
							 len + sizeof(*ip6h),
							 0);
		}
		ip6h->version = 6;
		ip6h->nexthdr = proto;
		ip6h->hop_limit = 255;
		if (flow) {
			ip6h->flow_lbl[0] = (flow >> 16) & 0xf;
			ip6h->flow_lbl[1] = (flow >> 8) & 0xff;
			ip6h->flow_lbl[2] = (flow >> 0) & 0xff;
		}

		tap_send(c, buf, len + sizeof(*ip6h) + sizeof(*eh), 1);
	}
}

/**
 * tap4_handler() - IPv4 and ARP packet handler for tap file descriptor
 * @c:		Execution context
 * @msg:	Array of messages with the same L3 protocol
 * @count:	Count of messages with the same L3 protocol
 * @now:	Current timestamp
 * @first:	First call for an IPv4 packet in this batch
 *
 * Return: count of packets consumed by handlers
 */
static int tap4_handler(struct ctx *c, struct tap_msg *msg, size_t count,
			struct timespec *now, int first)
{
	char buf_s[INET_ADDRSTRLEN] __attribute((__unused__));
	char buf_d[INET_ADDRSTRLEN] __attribute((__unused__));
	struct ethhdr *eh = (struct ethhdr *)msg[0].start;
	struct iphdr *iph, *prev_iph = NULL;
	struct udphdr *uh, *prev_uh = NULL;
	size_t len = msg[0].len;
	unsigned int i;
	char *l4h;

	if (!c->v4)
		return count;

	if (len < sizeof(*eh) + sizeof(*iph))
		return 1;

	if (arp(c, eh, len) || dhcp(c, eh, len))
		return 1;

	for (i = 0; i < count; i++) {
		len = msg[i].len;
		if (len < sizeof(*eh) + sizeof(*iph))
			return 1;

		eh = (struct ethhdr *)msg[i].start;
		iph = (struct iphdr *)(eh + 1);
		l4h = (char *)iph + iph->ihl * 4;

		if (first && c->addr4_seen != iph->saddr) {
			c->addr4_seen = iph->saddr;
			proto_update_l2_buf(NULL, NULL, &c->addr4_seen);
		}

		msg[i].l4h = l4h;
		msg[i].l4_len = len - ((intptr_t)l4h - (intptr_t)eh);

		if (iph->protocol != IPPROTO_TCP &&
		    iph->protocol != IPPROTO_UDP)
			break;

		if (len < sizeof(*uh))
			break;

		uh = (struct udphdr *)l4h;

		if (!i) {
			prev_iph = iph;
			prev_uh = uh;
			continue;
		}

		if (iph->tos		!= prev_iph->tos	||
		    iph->frag_off	!= prev_iph->frag_off	||
		    iph->protocol	!= prev_iph->protocol	||
		    iph->saddr		!= prev_iph->saddr	||
		    iph->daddr		!= prev_iph->daddr	||
		    uh->source		!= prev_uh->source	||
		    uh->dest		!= prev_uh->dest)
			break;

		prev_iph = iph;
		prev_uh = uh;
	}

	eh = (struct ethhdr *)msg[0].start;
	iph = (struct iphdr *)(eh + 1);

	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP ||
	    iph->protocol == IPPROTO_SCTP) {
		uh = (struct udphdr *)msg[0].l4h;

		if (msg[0].len < sizeof(*uh))
			return 1;

		debug("%s (%i) from tap: %s:%i -> %s:%i (%i packet%s)",
		      IP_PROTO_STR(iph->protocol), iph->protocol,
		      inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
		      ntohs(uh->source),
		      inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)),
		      ntohs(uh->dest),
		      i, i > 1 ? "s" : "");
	} else if (iph->protocol == IPPROTO_ICMP) {
		debug("icmp from tap: %s -> %s",
		      inet_ntop(AF_INET, &iph->saddr, buf_s, sizeof(buf_s)),
		      inet_ntop(AF_INET, &iph->daddr, buf_d, sizeof(buf_d)));
	}

	if (iph->protocol == IPPROTO_TCP)
		return tcp_tap_handler(c, AF_INET, &iph->daddr, msg, i, now);

	if (iph->protocol == IPPROTO_UDP)
		return udp_tap_handler(c, AF_INET, &iph->daddr, msg, i, now);

	if (iph->protocol == IPPROTO_ICMP)
		icmp_tap_handler(c, AF_INET, &iph->daddr, msg, 1, now);

	return 1;
}

/**
 * tap6_handler() - IPv6 packet handler for tap file descriptor
 * @c:		Execution context
 * @msg:	Array of messages with the same L3 protocol
 * @count:	Count of messages with the same L3 protocol
 * @now:	Current timestamp
 * @first:	First call for an IPv6 packet in this batch
 *
 * Return: count of packets consumed by handlers
 */
static int tap6_handler(struct ctx *c, struct tap_msg *msg, size_t count,
			struct timespec *now, int first)
{
	char buf_s[INET6_ADDRSTRLEN] __attribute((__unused__));
	char buf_d[INET6_ADDRSTRLEN] __attribute((__unused__));
	struct ethhdr *eh = (struct ethhdr *)msg[0].start;
	struct udphdr *uh, *prev_uh = NULL;
	uint8_t proto = 0, prev_proto = 0;
	size_t len = msg[0].len;
	struct ipv6hdr *ip6h;
	unsigned int i;
	char *l4h;

	if (!c->v6)
		return count;

	if (len < sizeof(*eh) + sizeof(*ip6h))
		return 1;

	if (ndp(c, eh, len) || dhcpv6(c, eh, len))
		return 1;

	for (i = 0; i < count; i++) {
		struct ipv6hdr *p_ip6h;

		len = msg[i].len;
		if (len < sizeof(*eh) + sizeof(*ip6h))
			return 1;

		eh = (struct ethhdr *)msg[i].start;
		ip6h = (struct ipv6hdr *)(eh + 1);
		l4h = ipv6_l4hdr(ip6h, &proto);

		msg[i].l4h = l4h;
		msg[i].l4_len = len - ((intptr_t)l4h - (intptr_t)eh);

		if (first) {
			if (IN6_IS_ADDR_LINKLOCAL(&ip6h->saddr)) {
				c->addr6_ll_seen = ip6h->saddr;

				if (IN6_IS_ADDR_UNSPECIFIED(&c->addr6_seen)) {
					c->addr6_seen = ip6h->saddr;
				}
			} else {
				c->addr6_seen = ip6h->saddr;
			}
		}

		ip6h->saddr = c->addr6;

		if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
			break;

		if (len < sizeof(*uh))
			break;

		uh = (struct udphdr *)l4h;

		if (!i) {
			p_ip6h = ip6h;
			prev_proto = proto;
			prev_uh = uh;
			continue;
		}

		if (proto		!= prev_proto		||
		    memcmp(&ip6h->saddr, &p_ip6h->saddr, sizeof(ip6h->saddr)) ||
		    memcmp(&ip6h->daddr, &p_ip6h->daddr, sizeof(ip6h->daddr)) ||
		    uh->source		!= prev_uh->source	||
		    uh->dest		!= prev_uh->dest)
			break;

		p_ip6h = ip6h;
		prev_proto = proto;
		prev_uh = uh;
	}

	if (prev_proto)
		proto = prev_proto;

	eh = (struct ethhdr *)msg[0].start;
	ip6h = (struct ipv6hdr *)(eh + 1);

	if (proto == IPPROTO_ICMPV6) {
		debug("icmpv6 from tap: %s ->\n\t%s",
		      inet_ntop(AF_INET6, &ip6h->saddr, buf_s, sizeof(buf_s)),
		      inet_ntop(AF_INET6, &ip6h->daddr, buf_d, sizeof(buf_d)));
	} else if (proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
		   proto == IPPROTO_SCTP) {
		uh = (struct udphdr *)msg[0].l4h;

		if (msg[0].len < sizeof(*uh))
			return 1;

		debug("%s (%i) from tap: [%s]:%i\n\t-> [%s]:%i (%i packet%s)",
		      IP_PROTO_STR(proto), proto,
		      inet_ntop(AF_INET6, &ip6h->saddr, buf_s, sizeof(buf_s)),
		      ntohs(uh->source),
		      inet_ntop(AF_INET6, &ip6h->daddr, buf_d, sizeof(buf_d)),
		      ntohs(uh->dest),
		      i, i > 1 ? "s" : "");
	}

	if (proto == IPPROTO_TCP)
		return tcp_tap_handler(c, AF_INET6, &ip6h->daddr, msg, i, now);

	if (proto == IPPROTO_UDP)
		return udp_tap_handler(c, AF_INET6, &ip6h->daddr, msg, i, now);

	if (proto == IPPROTO_ICMPV6)
		icmp_tap_handler(c, AF_INET6, &ip6h->daddr, msg, 1, now);

	return 1;
}

/**
 * tap_handler_passt() - Packet handler for AF_UNIX file descriptor
 * @c:		Execution context
 * @now:	Current timestamp
 *
 * Return: -ECONNRESET on receive error, 0 otherwise
 */
static int tap_handler_passt(struct ctx *c, struct timespec *now)
{
	int msg_count = 0, same, i = 0, first_v4 = 1, first_v6 = 1;
	struct tap_msg msg[TAP_MSGS];
	struct ethhdr *eh;
	char *p = pkt_buf;
	ssize_t n, rem;

	n = recv(c->fd_tap, p, TAP_BUF_FILL, MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_tap, NULL);
		close(c->fd_tap);

		return -ECONNRESET;
	}

	while (n > (ssize_t)sizeof(uint32_t)) {
		ssize_t len = ntohl(*(uint32_t *)p);

		p += sizeof(uint32_t);
		n -= sizeof(uint32_t);

		if (len < (ssize_t)sizeof(*eh))
			return 0;

		/* At most one packet might not fit in a single read */
		if (len > n) {
			rem = recv(c->fd_tap, p + n, len - n, MSG_DONTWAIT);
			if ((n += rem) != len)
				return 0;
		}

		pcap(p, len);

		msg[msg_count].start = p;
		msg[msg_count++].len = len;

		n -= len;
		p += len;
	}

	while (i < msg_count) {
		eh = (struct ethhdr *)msg[i].start;

		if (memcmp(c->mac_guest, eh->h_source, ETH_ALEN)) {
			memcpy(c->mac_guest, eh->h_source, ETH_ALEN);
			proto_update_l2_buf(c->mac_guest, NULL, NULL);
		}

		switch (ntohs(eh->h_proto)) {
		case ETH_P_ARP:
			tap4_handler(c, msg + i, 1, now, 1);
			i++;
			break;
		case ETH_P_IP:
			for (same = 1; i + same < msg_count &&
				       same < UIO_MAXIOV; same++) {
				struct tap_msg *next = &msg[i + same];

				eh = (struct ethhdr *)next->start;
				if (ntohs(eh->h_proto) != ETH_P_IP)
					break;
			}

			i += tap4_handler(c, msg + i, same, now, first_v4);
			first_v4 = 0;
			break;
		case ETH_P_IPV6:
			for (same = 1; i + same < msg_count &&
				       same < UIO_MAXIOV; same++) {
				struct tap_msg *next = &msg[i + same];

				eh = (struct ethhdr *)next->start;
				if (ntohs(eh->h_proto) != ETH_P_IPV6)
					break;
			}

			i += tap6_handler(c, msg + i, same, now, first_v6);
			first_v6 = 0;
			break;
		default:
			i++;
			break;
		}
	}

	return 0;
}

/**
 * tap_handler_pasta() - Packet handler for tuntap file descriptor
 * @c:		Execution context
 * @now:	Current timestamp
 *
 * Return: -ECONNRESET on receive error, 0 otherwise
 */
static int tap_handler_pasta(struct ctx *c, struct timespec *now)
{
	struct tap_msg msg = { .start = pkt_buf };
	ssize_t n;

	while ((n = read(c->fd_tap, pkt_buf, TAP_BUF_BYTES)) > 0) {
		struct ethhdr *eh = (struct ethhdr *)pkt_buf;
		msg.len = n;

		pcap(msg.start, msg.len);

		if (memcmp(c->mac_guest, eh->h_source, ETH_ALEN)) {
			memcpy(c->mac_guest, eh->h_source, ETH_ALEN);
			proto_update_l2_buf(c->mac_guest, NULL, NULL);
		}

		switch (ntohs(eh->h_proto)) {
		case ETH_P_ARP:
			tap4_handler(c, &msg, 1, now, 1);
			break;
		case ETH_P_IP:
			tap4_handler(c, &msg, 1, now, 1);
			break;
		case ETH_P_IPV6:
			tap6_handler(c, &msg, 1, now, 1);
			break;
		}
	}

	if (!n || errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		return 0;

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_tap, NULL);
	close(c->fd_tap);

	return -ECONNRESET;
}

/**
 * tap_sock_init_unix() - Create and bind AF_UNIX socket, wait for connection
 * @c:		Execution context
 */
static void tap_sock_init_unix(struct ctx *c)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0), ex;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	int i, ret;

	if (c->fd_tap_listen)
		close(c->fd_tap_listen);

	if (fd < 0) {
		perror("UNIX socket");
		exit(EXIT_FAILURE);
	}
	c->fd_tap_listen = fd;

	for (i = 1; i < UNIX_SOCK_MAX; i++) {
		snprintf(addr.sun_path, UNIX_PATH_MAX, UNIX_SOCK_PATH, i);

		ex = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
		ret = connect(ex, (const struct sockaddr *)&addr, sizeof(addr));
		if (!ret || (errno != ENOENT && errno != ECONNREFUSED)) {
			close(ex);
			continue;
		}
		close(ex);

		unlink(addr.sun_path);
		if (!bind(fd, (const struct sockaddr *)&addr, sizeof(addr)))
			break;
	}

	if (i == UNIX_SOCK_MAX) {
		perror("UNIX socket bind");
		exit(EXIT_FAILURE);
	}

	info("UNIX domain socket bound at %s\n", addr.sun_path);
	chmod(addr.sun_path,
	      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	pcap_init(c, i);

	listen(fd, 0);

	info("You can now start qrap:");
	info("    ./qrap 5 kvm ... -net socket,fd=5 -net nic,model=virtio");
	info("or directly qemu, patched with:");
	info("    qemu/0001-net-Allow-also-UNIX-domain-sockets-to-be-used-as-net.patch");
	info("as follows:");
	info("    kvm ... -net socket,connect=" UNIX_SOCK_PATH
	     " -net nic,model=virtio", i);

	c->fd_tap = accept(fd, NULL, NULL);
}

static int tun_ns_fd = -1;

/**
 * tap_sock_init_tun_ns() - Create tuntap file descriptor in namespace
 * @c:		Execution context
 */
static int tap_sock_init_tun_ns(void *target_pid)
{
	int fd;

	if (ns_enter(*(int *)target_pid))
		goto fail;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
		goto fail;

	fcntl(fd, F_SETFL, O_NONBLOCK);

	tun_ns_fd = fd;

	return 0;

fail:
	tun_ns_fd = -1;
	return 0;
}

/**
 * tap_sock_init_tun() - Set up tuntap file descriptor
 * @c:		Execution context
 */
static void tap_sock_init_tun(struct ctx *c)
{
	struct ifreq ifr = { .ifr_name = "pasta0",
			     .ifr_flags = IFF_TAP | IFF_NO_PI,
			   };
	char ns_fn_stack[NS_FN_STACK_SIZE];

	clone(tap_sock_init_tun_ns, ns_fn_stack + sizeof(ns_fn_stack) / 2,
	      CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD,
	      (void *)&c->pasta_pid);

	if (tun_ns_fd == -1) {
		err("Failed to open tun socket in namespace");
		exit(EXIT_FAILURE);
	}

	if (ioctl(tun_ns_fd, TUNSETIFF, &ifr)) {
		perror("TUNSETIFF ioctl");
		exit(EXIT_FAILURE);
	}

	pcap_init(c, c->pasta_pid);

	c->fd_tap = tun_ns_fd;
}

/**
 * tap_sock_init() - Create and set up AF_UNIX socket or tuntap file descriptor
 * @c:		Execution context
 */
void tap_sock_init(struct ctx *c)
{
	struct epoll_event ev = { 0 };

	if (c->fd_tap) {
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_tap, NULL);
		close(c->fd_tap);
	}

	if (c->mode == MODE_PASST)
		tap_sock_init_unix(c);
	else
		tap_sock_init_tun(c);

	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.fd = c->fd_tap;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, c->fd_tap, &ev);
}

/**
 * tap_handler() - Packet handler for AF_UNIX or tuntap file descriptor
 * @c:		Execution context
 * @events:	epoll events
 * @now:	Current timestamp
 */
void tap_handler(struct ctx *c, uint32_t events, struct timespec *now)
{
	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))
		goto fail;

	if ((c->mode == MODE_PASST && tap_handler_passt(c, now)) ||
	    (c->mode == MODE_PASTA && tap_handler_pasta(c, now)))
		goto fail;

	return;
fail:
	tap_sock_init(c);
}

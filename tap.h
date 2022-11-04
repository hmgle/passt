/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TAP_H
#define TAP_H

struct in_addr tap_ip4_daddr(const struct ctx *c);
void tap_udp4_send(const struct ctx *c, struct in_addr src, in_port_t sport,
		   struct in_addr dst, in_port_t dport,
		   const void *in, size_t len);
void tap_icmp4_send(const struct ctx *c, struct in_addr src, struct in_addr dst,
		    void *in, size_t len);
const struct in6_addr *tap_ip6_daddr(const struct ctx *c,
				     const struct in6_addr *src);
void tap_udp6_send(const struct ctx *c,
		   const struct in6_addr *src, in_port_t sport,
		   const struct in6_addr *dst, in_port_t dport,
		   uint32_t flow, const void *in, size_t len);
void tap_icmp6_send(const struct ctx *c,
		    const struct in6_addr *src, const struct in6_addr *dst,
		    void *in, size_t len);
int tap_send(const struct ctx *c, const void *data, size_t len);
void tap_handler(struct ctx *c, int fd, uint32_t events,
		 const struct timespec *now);
void tap_sock_init(struct ctx *c);

#endif /* TAP_H */

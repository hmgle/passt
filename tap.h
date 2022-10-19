/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TAP_H
#define TAP_H

in_addr_t tap_ip4_daddr(const struct ctx *c);
const struct in6_addr *tap_ip6_daddr(const struct ctx *c,
				     const struct in6_addr *src);
void tap_ip4_send(const struct ctx *c, in_addr_t src, uint8_t proto,
		  const char *in, size_t len);
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

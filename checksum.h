/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H

struct icmphdr;
struct icmp6hdr;

uint32_t sum_16b(const void *buf, size_t len);
uint16_t csum_fold(uint32_t sum);
uint16_t csum_unaligned(const void *buf, size_t len, uint32_t init);
void csum_icmp4(struct icmphdr *ih, const void *payload, size_t len);
void csum_icmp6(struct icmp6hdr *icmp6hr,
		const struct in6_addr *saddr, const struct in6_addr *daddr,
		const void *payload, size_t len);
void csum_tcp4(struct iphdr *iph);
uint16_t csum(const void *buf, size_t len, uint32_t init);

#endif /* CHECKSUM_H */

// SPDX-License-Identifier: AGPL-3.0-or-later AND BSD-3-Clause

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * checksum.c - TCP/IP checksum routines
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * This file also contains code originally licensed under the following terms:
 *
 * Copyright (c) 2014-2016, The Regents of the University of California.
 * Copyright (c) 2016-2017, Nefeli Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the names of the copyright holders nor the names of their
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * See the comment to csum_avx2() for further details.
 */

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

/* Checksums are optional for UDP over IPv4, so we usually just set
 * them to 0.  Change this to 1 to calculate real UDP over IPv4
 * checksums
 */
#define UDP4_REAL_CHECKSUMS	0

/**
 * sum_16b() - Calculate sum of 16-bit words
 * @buf:	Input buffer
 * @len:	Buffer length
 *
 * Return: 32-bit sum of 16-bit words
*/
uint32_t sum_16b(const void *buf, size_t len)
{
	const uint16_t *p = buf;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}

	if (len > 0)
		sum += *p & htons(0xff00);

	return sum;
}

/**
 * csum_fold() - Fold long sum for IP and TCP checksum
 * @sum:	Original long sum
 *
 * Return: 16-bit folded sum
 */
uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

/**
 * csum_unaligned() - Compute TCP/IP-style checksum for not 32-byte aligned data
 * @buf:	Input data
 * @len:	Input length
 * @init:	Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 16-bit IPv4-style checksum
 */
#if CSUM_UNALIGNED_NO_IPA
__attribute__((__noipa__))	/* See comment in Makefile */
#endif
uint16_t csum_unaligned(const void *buf, size_t len, uint32_t init)
{
	return (uint16_t)~csum_fold(sum_16b(buf, len) + init);
}

/**
 * csum_ip4_header() - Calculate and set IPv4 header checksum
 * @ip4h:	IPv4 header
 */
void csum_ip4_header(struct iphdr *ip4h)
{
	ip4h->check = 0;
	ip4h->check = csum_unaligned(ip4h, (size_t)ip4h->ihl * 4, 0);
}

/**
 * csum_udp4() - Calculate and set checksum for a UDP over IPv4 packet
 * @udp4hr:	UDP header, initialised apart from checksum
 * @saddr:	IPv4 source address
 * @daddr:	IPv4 destination address
 * @payload:	ICMPv4 packet payload
 * @len:	Length of @payload (not including UDP)
 */
void csum_udp4(struct udphdr *udp4hr, in_addr_t saddr, in_addr_t daddr,
	       const void *payload, size_t len)
{
	/* UDP checksums are optional, so don't bother */
	udp4hr->check = 0;

	if (UDP4_REAL_CHECKSUMS) {
		/* UNTESTED: if we did want real UDPv4 checksums, this
		 * is roughly what we'd need */
		uint32_t psum = csum_fold(htonl(saddr))
			+ csum_fold(htonl(daddr))
			+ htons(len + sizeof(*udp4hr))
			+ htons(IPPROTO_UDP);
		/* Add in partial checksum for the UDP header alone */
		psum += sum_16b(udp4hr, sizeof(*udp4hr));
		udp4hr->check = csum_unaligned(payload, len, psum);
	}
}

/**
 * csum_icmp4() - Calculate and set checksum for an ICMP packet
 * @icmp4hr:	ICMP header, initialised apart from checksum
 * @payload:	ICMP packet payload
 * @len:	Length of @payload (not including ICMP header)
 */
void csum_icmp4(struct icmphdr *icmp4hr, const void *payload, size_t len)
{
	/* Partial checksum for ICMP header alone */
	uint32_t psum = sum_16b(icmp4hr, sizeof(*icmp4hr));

	icmp4hr->checksum = 0;
	icmp4hr->checksum = csum_unaligned(payload, len, psum);
}

/**
 * csum_udp6() - Calculate and set checksum for a UDP over IPv6 packet
 * @udp6hr:	UDP header, initialised apart from checksum
 * @payload:	UDP packet payload
 * @len:	Length of @payload (not including UDP header)
 */
void csum_udp6(struct udphdr *udp6hr,
	       const struct in6_addr *saddr, const struct in6_addr *daddr,
	       const void *payload, size_t len)
{
	/* Partial checksum for the pseudo-IPv6 header */
	uint32_t psum = sum_16b(saddr, sizeof(*saddr)) +
		        sum_16b(daddr, sizeof(*daddr)) +
		        htons(len + sizeof(*udp6hr)) + htons(IPPROTO_UDP);

	udp6hr->check = 0;
	/* Add in partial checksum for the UDP header alone */
	psum += sum_16b(udp6hr, sizeof(*udp6hr));
	udp6hr->check = csum_unaligned(payload, len, psum);
}

/**
 * csum_icmp6() - Calculate and set checksum for an ICMPv6 packet
 * @icmp6hr:	ICMPv6 header, initialised apart from checksum
 * @saddr:	IPv6 source address
 * @daddr:	IPv6 destination address
 * @payload:	ICMP packet payload
 * @len:	Length of @payload (not including ICMPv6 header)
 */
void csum_icmp6(struct icmp6hdr *icmp6hr,
		const struct in6_addr *saddr, const struct in6_addr *daddr,
		const void *payload, size_t len)
{
	/* Partial checksum for the pseudo-IPv6 header */
	uint32_t psum = sum_16b(saddr, sizeof(*saddr)) +
		        sum_16b(daddr, sizeof(*daddr)) +
		        htons(len + sizeof(*icmp6hr)) + htons(IPPROTO_ICMPV6);

	icmp6hr->icmp6_cksum = 0;
	/* Add in partial checksum for the ICMPv6 header alone */
	psum += sum_16b(icmp6hr, sizeof(*icmp6hr));
	icmp6hr->icmp6_cksum = csum_unaligned(payload, len, psum);
}

#ifdef __AVX2__
#include <immintrin.h>

/**
 * csum_avx2() - Compute 32-bit checksum using AVX2 SIMD instructions
 * @buf:	Input buffer, must be aligned to 32-byte boundary
 * @len:	Input length
 * @init:	Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 32-bit checksum, not complemented, not folded
 *
 * This implementation is mostly sourced from BESS ("Berkeley Extensible
 * Software Switch"), core/utils/checksum.h, distributed under the terms of the
 * 3-Clause BSD license. Notable changes:
 * - input buffer data is loaded (streamed) with a non-temporal aligned hint
 *   (VMOVNTDQA, _mm256_stream_load_si256() intrinsic) instead of the original
 *   unaligned load with temporal hint (VMOVDQU, _mm256_loadu_si256() intrinsic)
 *   given that the input buffer layout guarantees 32-byte alignment of TCP and
 *   UDP headers, and that the data is not used immediately afterwards, reducing
 *   cache pollution significantly and latency (e.g. on Intel Skylake: 0 instead
 *   of 7)
 * - read from four streams in parallel as long as we have more than 128 bytes,
 *   not just two
 * - replace the ADCQ implementation for the portion remaining after the
 *   checksum computation for 128-byte blocks by a load/unpack/add loop on a
 *   single stream, and do the rest with a for loop, auto-vectorisation seems to
 *   outperforms the original hand-coded loop there
 * - sum_a/sum_b unpacking is interleaved and not sequential to reduce stalls
 * - coding style adaptation
 */
static uint32_t csum_avx2(const void *buf, size_t len, uint32_t init)
{
	__m256i a, b, sum256, sum_a_hi, sum_a_lo, sum_b_hi, sum_b_lo, c, d;
	__m256i __sum_a_hi, __sum_a_lo, __sum_b_hi, __sum_b_lo;
	const __m256i *buf256 = (const __m256i *)buf;
	const uint64_t *buf64;
	const uint16_t *buf16;
	uint64_t sum64 = init;
	int odd = len & 1;
	__m128i sum128;
	__m256i zero;

	zero = _mm256_setzero_si256();

	if (len < sizeof(__m256i) * 4)
		goto less_than_128_bytes;

	/* We parallelize two ymm streams to minimize register dependency:
	 *
	 * a: buf256,             buf256 + 2,             ...
	 * b:         buf256 + 1,             buf256 + 3, ...
	 */
	a = _mm256_stream_load_si256(buf256);
	b = _mm256_stream_load_si256(buf256 + 1);

	/* For each stream, accumulate unpackhi and unpacklo in parallel (as
	 * 4x64bit vectors, so that each upper 0000 can hold carries):
	 *
	 * 32B data: aaaaAAAA bbbbBBBB ccccCCCC ddddDDDD (1 letter: 1 byte)
	 * unpackhi: bbbb0000 BBBB0000 dddd0000 DDDD0000
	 * unpacklo: aaaa0000 AAAA0000 cccc0000 CCCC0000
	 */
	sum_a_hi = _mm256_unpackhi_epi32(a, zero);
	sum_b_hi = _mm256_unpackhi_epi32(b, zero);
	sum_a_lo = _mm256_unpacklo_epi32(a, zero);
	sum_b_lo = _mm256_unpacklo_epi32(b, zero);

	len -= sizeof(__m256i) * 2;
	buf256 += 2;

	/* As long as we have more than 128 bytes, (stream) load from four
	 * streams instead of two, interleaving loads and register usage, to
	 * further decrease stalls, but don't double the number of accumulators
	 * and don't make this a general case to keep branching reasonable.
	 */
	if (len >= sizeof(a) * 4) {
		a = _mm256_stream_load_si256(buf256);
		b = _mm256_stream_load_si256(buf256 + 1);
		c = _mm256_stream_load_si256(buf256 + 2);
		d = _mm256_stream_load_si256(buf256 + 3);
	}
	for (; len >= sizeof(a) * 4; len -= sizeof(a) * 4, buf256 += 4) {
		__sum_a_hi = _mm256_add_epi64(sum_a_hi,
					    _mm256_unpackhi_epi32(a, zero));
		__sum_b_hi = _mm256_add_epi64(sum_b_hi,
					    _mm256_unpackhi_epi32(b, zero));
		__sum_a_lo = _mm256_add_epi64(sum_a_lo,
					    _mm256_unpacklo_epi32(a, zero));
		__sum_b_lo = _mm256_add_epi64(sum_b_lo,
					    _mm256_unpacklo_epi32(b, zero));

		if (len >= sizeof(a) * 8) {
			a = _mm256_stream_load_si256(buf256 + 4);
			b = _mm256_stream_load_si256(buf256 + 5);
		}

		sum_a_hi = _mm256_add_epi64(__sum_a_hi,
					    _mm256_unpackhi_epi32(c, zero));
		sum_b_hi = _mm256_add_epi64(__sum_b_hi,
					    _mm256_unpackhi_epi32(d, zero));
		sum_a_lo = _mm256_add_epi64(__sum_a_lo,
					    _mm256_unpacklo_epi32(c, zero));
		sum_b_lo = _mm256_add_epi64(__sum_b_lo,
					    _mm256_unpacklo_epi32(d, zero));

		if (len >= sizeof(a) * 8) {
			c = _mm256_stream_load_si256(buf256 + 6);
			d = _mm256_stream_load_si256(buf256 + 7);
		}
	}

	for (; len >= sizeof(a) * 2; len -= sizeof(a) * 2, buf256 += 2) {
		a = _mm256_stream_load_si256(buf256);
		b = _mm256_stream_load_si256(buf256 + 1);

		sum_a_hi = _mm256_add_epi64(sum_a_hi,
					    _mm256_unpackhi_epi32(a, zero));
		sum_b_hi = _mm256_add_epi64(sum_b_hi,
					    _mm256_unpackhi_epi32(b, zero));
		sum_a_lo = _mm256_add_epi64(sum_a_lo,
					    _mm256_unpacklo_epi32(a, zero));
		sum_b_lo = _mm256_add_epi64(sum_b_lo,
					    _mm256_unpacklo_epi32(b, zero));
	}

	/* Fold four 256bit sums into one 128-bit sum. */
	sum256 = _mm256_add_epi64(_mm256_add_epi64(sum_a_hi, sum_b_lo),
				  _mm256_add_epi64(sum_b_hi, sum_a_lo));
	sum128 = _mm_add_epi64(_mm256_extracti128_si256(sum256, 0),
			       _mm256_extracti128_si256(sum256, 1));

	/* Fold 128-bit sum into 64 bits. */
	sum64 += _mm_extract_epi64(sum128, 0) + _mm_extract_epi64(sum128, 1);

less_than_128_bytes:
	for (; len >= sizeof(a); len -= sizeof(a), buf256++) {
		a = _mm256_stream_load_si256(buf256);

		sum_a_hi = _mm256_unpackhi_epi32(a, zero);
		sum_a_lo = _mm256_unpacklo_epi32(a, zero);

		sum256 = _mm256_add_epi64(sum_a_hi, sum_a_lo);
		sum128 = _mm_add_epi64(_mm256_extracti128_si256(sum256, 0),
				       _mm256_extracti128_si256(sum256, 1));

		sum64 += _mm_extract_epi64(sum128, 0);
		sum64 += _mm_extract_epi64(sum128, 1);
	}
	buf64 = (const uint64_t *)buf256;

	/* Repeat 16-bit one's complement sum (at sum64). */
	buf16 = (const uint16_t *)buf64;
	while (len >= sizeof(uint16_t)) {
		sum64 += *buf16++;
		len -= sizeof(uint16_t);
	}

	/* Add remaining 8 bits to the one's complement sum. */
	if (odd)
		sum64 += *(const uint8_t *)buf16;

	/* Reduce 64-bit unsigned int to 32-bit unsigned int. */
	sum64 = (sum64 >> 32) + (sum64 & 0xffffffff);
	sum64 += sum64 >> 32;

	return (uint32_t)sum64;
}

/**
 * csum() - Compute TCP/IP-style checksum
 * @buf:	Input buffer, must be aligned to 32-byte boundary
 * @len:	Input length
 * @init:	Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 16-bit folded, complemented checksum sum
 */
uint16_t csum(const void *buf, size_t len, uint32_t init)
{
	return (uint16_t)~csum_fold(csum_avx2(buf, len, init));
}

#else /* __AVX2__ */

/**
 * csum() - Compute TCP/IP-style checksum
 * @buf:	Input buffer
 * @len:	Input length
 * @sum:	Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 16-bit folded, complemented checksum
 */
uint16_t csum(const void *buf, size_t len, uint32_t init)
{
	return csum_unaligned(buf, len, init);
}

#endif /* !__AVX2__ */

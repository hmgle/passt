// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * siphash.c - SipHash routines
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * This is an implementation of the SipHash-2-4-64 functions needed for TCP
 * initial sequence numbers and socket lookup table hash for IPv4 and IPv6, see:
 *
 *	Aumasson, J.P. and Bernstein, D.J., 2012, December. SipHash: a fast
 *	short-input PRF. In International Conference on Cryptology in India
 *	(pp. 489-508). Springer, Berlin, Heidelberg.
 *
 *	http://cr.yp.to/siphash/siphash-20120918.pdf
 *
 * This includes code from the reference SipHash implementation at
 * https://github.com/veorq/SipHash/ originally licensed as follows:
 *
 * --
 *  SipHash reference C implementation
 *
 * Copyright (c) 2012-2021 Jean-Philippe Aumasson
 * <jeanphilippe.aumasson@gmail.com>
 * Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 * --
 *
 * and from the Linux kernel implementation (lib/siphash.c), originally licensed
 * as follows:
 *
 * --
 * Copyright (C) 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This file is provided under a dual BSD/GPLv2 license.
 * --
 *
 */

#include <stdint.h>

#include "siphash.h"

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define PREAMBLE(len)							  \
	uint64_t v[4] = { 0x736f6d6570736575ULL, 0x646f72616e646f6dULL,	  \
			  0x6c7967656e657261ULL, 0x7465646279746573ULL }; \
	uint64_t b = (uint64_t)(len) << 56;				  \
	uint32_t ret;							  \
	int __i;							  \
									  \
	do {								  \
		for (__i = sizeof(v) / sizeof(v[0]); __i >= 0; __i--)	  \
			v[__i] = k[__i % 2];				  \
	} while (0)

#define SIPROUND(n)							  \
	do {								  \
		for (__i = 0; __i < (n); __i++) {			  \
			v[0] += v[1];					  \
			v[1] = ROTL(v[1], 13) ^ v[0];			  \
			v[0] = ROTL(v[0], 32);				  \
			v[2] += v[3];					  \
			v[3] = ROTL(v[3], 16) ^ v[2];			  \
			v[0] += v[3];					  \
			v[3] = ROTL(v[3], 21) ^ v[0];			  \
			v[2] += v[1];					  \
			v[1] = ROTL(v[1], 17) ^ v[2];			  \
			v[2] = ROTL(v[2], 32);				  \
		}							  \
	} while (0)

#define POSTAMBLE							  \
	do {								  \
		v[3] ^= b;						  \
		SIPROUND(2);						  \
		v[0] ^= b;						  \
		v[2] ^= 0xff;						  \
		SIPROUND(4);						  \
		b = (v[0] ^ v[1]) ^ (v[2] ^ v[3]);			  \
		ret = (uint32_t)(b >> 32) ^ (uint32_t)b;		  \
		(void)ret;						  \
	} while (0)

/**
 * siphash_8b() - Table index or timestamp offset for TCP over IPv4 (8 bytes in)
 * @in:		Input data (remote address and two ports, or two addresses)
 * @k:		Hash function key, 128 bits
 *
 * Return: the 64-bit hash output
 */
uint64_t siphash_8b(const uint8_t *in, const uint64_t *k)
{
	PREAMBLE(8);
	v[3] ^= *(uint64_t *)in;
	SIPROUND(2);
	v[0] ^= *(uint64_t *)in;
	POSTAMBLE;

	return b;
}

/**
 * siphash_12b() - Initial sequence number for TCP over IPv4 (12 bytes in)
 * @in:		Input data (two addresses, two ports)
 * @k:		Hash function key, 128 bits
 *
 * Return: 32 bits obtained by XORing the two halves of the 64-bit hash output
 */
uint32_t siphash_12b(const uint8_t *in, const uint64_t *k)
{
	uint32_t *in32 = (uint32_t *)in;
	uint64_t combined;

	combined = (uint64_t)(*(in32 + 1)) << 32 | *in32;

	PREAMBLE(12);
	v[3] ^= combined;
	SIPROUND(2);
	v[0] ^= combined;
	b |= *(in32 + 2);
	POSTAMBLE;

	return ret;
}

/**
 * siphash_20b() - Table index for TCP over IPv6 (20 bytes in)
 * @in:		Input data (remote address, two ports)
 * @k:		Hash function key, 128 bits
 *
 * Return: the 64-bit hash output
 */
#if SIPHASH_20B_NOINLINE
__attribute__((__noinline__))	/* See comment in Makefile */
#endif
uint64_t siphash_20b(const uint8_t *in, const uint64_t *k)
{
	uint32_t *in32 = (uint32_t *)in;
	uint64_t combined;
	int i;

	PREAMBLE(20);

	for (i = 0; i < 2; i++, in32 += 2) {
		combined = (uint64_t)(*(in32 + 1)) << 32 | *in32;
		v[3] ^= combined;
		SIPROUND(2);
		v[0] ^= combined;
	}

	b |= *in32;
	POSTAMBLE;

	return b;
}

/**
 * siphash_32b() - Timestamp offset for TCP over IPv6 (32 bytes in)
 * @in:		Input data (two addresses)
 * @k:		Hash function key, 128 bits
 *
 * Return: the 64-bit hash output
 */
uint32_t siphash_32b(const uint8_t *in, const uint64_t *k)
{
	uint64_t *in64 = (uint64_t *)in;
	int i;

	PREAMBLE(32);

	for (i = 0; i < 4; i++, in64++) {
		v[3] ^= *in64;
		SIPROUND(2);
		v[0] ^= *in64;
	}

	POSTAMBLE;

	return b;
}

/**
 * siphash_36b() - Initial sequence number for TCP over IPv6 (36 bytes in)
 * @in:		Input data (two addresses, two ports)
 * @k:		Hash function key, 128 bits
 *
 * Return: 32 bits obtained by XORing the two halves of the 64-bit hash output
 */
uint32_t siphash_36b(const uint8_t *in, const uint64_t *k)
{
	uint32_t *in32 = (uint32_t *)in;
	uint64_t combined;
	int i;

	PREAMBLE(36);

	for (i = 0; i < 4; i++, in32 += 2) {
		combined = (uint64_t)(*(in32 + 1)) << 32 | *in32;
		v[3] ^= combined;
		SIPROUND(2);
		v[0] ^= combined;
	}

	b |= *in32;
	POSTAMBLE;

	return ret;
}

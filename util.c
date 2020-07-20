/* MERD - MacVTap Egress and Routing Daemon
 *
 * util.c - Convenience helpers
 *
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * License: GPLv2
 *
 */

#include <stdint.h>
#include <stddef.h>

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
 * csum_ipv4() - Calculate IPv4 checksum
 * @buf:	Packet buffer, L3 headers
 * @len:	Total L3 packet length
 *
 * Return: 16-bit IPv4-style checksum
 */
uint16_t csum_ip4(void *buf, size_t len)
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

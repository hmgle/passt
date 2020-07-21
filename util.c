/* PASST - Plug A Simple Socket Transport
 *
 * util.c - Convenience helpers
 *
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * License: GPLv2
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>

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

unsigned char *ipv6_l4hdr(struct ipv6hdr *ip6h, uint8_t *proto)
{
	int offset, len, hdrlen;
	struct ipv6_opt_hdr *o;
	uint8_t nh;

	len = ntohs(ip6h->payload_len);
	offset = 0;

	while (offset < len) {
		if (!offset) {
			nh = ip6h->nexthdr;
			hdrlen = sizeof(struct ipv6hdr);
		} else {
			nh = o->nexthdr;
			hdrlen = (o->hdrlen + 1) * 8;
		}

		if (nh == 59)
			return NULL;

		if (nh == 0   || nh == 43  || nh == 44  || nh == 50  ||
		    nh == 51  || nh == 60  || nh == 135 || nh == 139 ||
		    nh == 140 || nh == 253 || nh == 254) {
			offset += hdrlen;
			o = (struct ipv6_opt_hdr *)(unsigned char *)ip6h +
								    offset;
		} else {
			*proto = nh;
			return (unsigned char *)(ip6h + 1) + offset;
		}
	}

	return NULL;
}

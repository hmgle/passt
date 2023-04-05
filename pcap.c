// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * pcap.c - Packet capture for PASST/PASTA
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net/if.h>

#include "util.h"
#include "passt.h"
#include "log.h"

#define PCAP_VERSION_MINOR 4

static int pcap_fd = -1;

/* See pcap.h from libpcap, or pcap-savefile(5) */
static const struct {
	uint32_t magic;
#define PCAP_MAGIC		0xa1b2c3d4

	uint16_t major;
#define PCAP_VERSION_MAJOR	2

	uint16_t minor;
#define PCAP_VERSION_MINOR	4

	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;

	uint32_t linktype;
#define PCAP_LINKTYPE_ETHERNET	1
} pcap_hdr = {
	PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR, 0, 0, ETH_MAX_MTU,
	PCAP_LINKTYPE_ETHERNET
};

struct pcap_pkthdr {
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

/**
 * pcap_frame() - Capture a single frame to pcap file with given timestamp
 * @pkt:	Pointer to data buffer, including L2 headers
 * @len:	L2 packet length
 * @tv:		Timestamp
 *
 * Returns: 0 on success, -errno on error writing to the file
 */
static int pcap_frame(const char *pkt, size_t len, const struct timeval *tv)
{
	struct pcap_pkthdr h;

	h.tv_sec = tv->tv_sec;
	h.tv_usec = tv->tv_usec;
	h.caplen = h.len = len;

	if (write(pcap_fd, &h, sizeof(h)) < 0 || write(pcap_fd, pkt, len) < 0)
		return -errno;

	return 0;
}

/**
 * pcap() - Capture a single frame to pcap file
 * @pkt:	Pointer to data buffer, including L2 headers
 * @len:	L2 packet length
 */
void pcap(const char *pkt, size_t len)
{
	struct timeval tv;

	if (pcap_fd == -1)
		return;

	gettimeofday(&tv, NULL);
	if (pcap_frame(pkt, len, &tv) != 0)
		debug("Cannot log packet, length %lu", len);
}

/**
 * pcap_multiple() - Capture multiple frames
 * @iov:	Array of iovecs, one entry per frame
 * @n:		Number of frames to capture
 * @offset:	Offset of the frame within each iovec buffer
 */
void pcap_multiple(const struct iovec *iov, unsigned int n, size_t offset)
{
	struct timeval tv;
	unsigned int i;

	if (pcap_fd == -1)
		return;

	gettimeofday(&tv, NULL);

	for (i = 0; i < n; i++) {
		if (pcap_frame((char *)iov[i].iov_base + offset,
			       iov[i].iov_len - offset, &tv) != 0) {
			debug("Cannot log packet, length %lu",
			      iov->iov_len - offset);
			return;
		}
	}
}

/**
 * pcap_init() - Initialise pcap file
 * @c:		Execution context
 */
void pcap_init(struct ctx *c)
{
	int flags = O_WRONLY | O_CREAT | O_TRUNC;

	if (pcap_fd != -1)
		return;

	if (!*c->pcap)
		return;

	flags |= c->foreground ? O_CLOEXEC : 0;
	pcap_fd = open(c->pcap, flags, S_IRUSR | S_IWUSR);
	if (pcap_fd == -1) {
		perror("open");
		return;
	}

	info("Saving packet capture to %s", c->pcap);

	if (write(pcap_fd, &pcap_hdr, sizeof(pcap_hdr)) < 0)
		warn("Cannot write PCAP header: %s", strerror(errno));
}

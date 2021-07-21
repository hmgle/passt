// SPDX-License-Identifier: AGPL-3.0-or-later

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

#define _GNU_SOURCE
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
#include <net/ethernet.h>
#include <unistd.h>
#include <net/if.h>

#include "util.h"
#include "passt.h"

#ifdef DEBUG

#define PCAP_PREFIX		"/tmp/passt_"
#define PCAP_PREFIX_PASTA	"/tmp/pasta_"
#define PCAP_ISO8601_FORMAT	"%FT%H:%M:%SZ"
#define PCAP_ISO8601_STR	"YYYY-MM-ddTHH:mm:ssZ"

#define PCAP_VERSION_MINOR 4

static int pcap_fd = -1;

/* See pcap.h from libpcap, or pcap-savefile(5) */
static struct {
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
 * pcap() - Capture a single frame to pcap file
 * @pkt:	Pointer to data buffer, including L2 headers
 * @len:	L2 packet length
 */
void pcap(char *pkt, size_t len)
{
	struct pcap_pkthdr h;
	struct timeval tv;

	if (pcap_fd == -1)
		return;

	gettimeofday(&tv, NULL);
	h.tv_sec = tv.tv_sec;
	h.tv_usec = tv.tv_usec;
	h.caplen = h.len = len;

	write(pcap_fd, &h, sizeof(h));
	write(pcap_fd, pkt, len);
}

/**
 * pcapm() - Capture multiple frames from message header to pcap file
 * @mh:		Pointer to sendmsg() message header buffer
 */
void pcapm(struct msghdr *mh)
{
	struct pcap_pkthdr h;
	struct timeval tv;
	unsigned int i;

	if (pcap_fd == -1)
		return;

	gettimeofday(&tv, NULL);
	h.tv_sec = tv.tv_sec;
	h.tv_usec = tv.tv_usec;

	for (i = 0; i < mh->msg_iovlen; i++) {
		struct iovec *iov = &mh->msg_iov[i];

		h.caplen = h.len = iov->iov_len - 4;
		write(pcap_fd, &h, sizeof(h));

		write(pcap_fd, (char *)iov->iov_base + 4, iov->iov_len - 4);
	}
}

/**
 * pcapm() - Capture multiple frames from multiple message headers to pcap file
 * @mmh:	Pointer to first sendmmsg() header
 */
void pcapmm(struct mmsghdr *mmh, unsigned int vlen)
{
	struct pcap_pkthdr h;
	struct timeval tv;
	unsigned int i, j;

	if (pcap_fd == -1)
		return;

	gettimeofday(&tv, NULL);
	h.tv_sec = tv.tv_sec;
	h.tv_usec = tv.tv_usec;

	for (i = 0; i < vlen; i++) {
		struct msghdr *mh = &mmh[i].msg_hdr;

		for (j = 0; j < mh->msg_iovlen; j++) {
			struct iovec *iov = &mh->msg_iov[j];

			h.caplen = h.len = iov->iov_len - 4;
			write(pcap_fd, &h, sizeof(h));

			write(pcap_fd, (char *)iov->iov_base + 4,
			      iov->iov_len - 4);
		}
	}
}

/**
 * pcap_init() - Initialise pcap file
 * @c:		Execution context
 * @index:	pcap name index: passt instance number or pasta target pid
 */
void pcap_init(struct ctx *c, int index)
{
	char name[] = PCAP_PREFIX PCAP_ISO8601_STR STR(UINT_MAX) ".pcap";
	struct timeval tv;
	struct tm *tm;

	if (pcap_fd != -1)
		close(pcap_fd);

	if (c->mode == MODE_PASTA)
		memcpy(name, PCAP_PREFIX_PASTA, sizeof(PCAP_PREFIX_PASTA));

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);
	strftime(name + strlen(PCAP_PREFIX), sizeof(PCAP_ISO8601_STR) - 1,
		 PCAP_ISO8601_FORMAT, tm);

	snprintf(name + strlen(PCAP_PREFIX) + strlen(PCAP_ISO8601_STR),
		 sizeof(name) - strlen(PCAP_PREFIX) - strlen(PCAP_ISO8601_STR),
		 "_%i.pcap", index);

	pcap_fd = open(name, O_WRONLY | O_CREAT | O_APPEND | O_DSYNC,
		       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (pcap_fd == -1) {
		perror("open");
		return;
	}

	info("Saving packet capture at %s", name);

	write(pcap_fd, &pcap_hdr, sizeof(pcap_hdr));
}

#else /* DEBUG */
void pcap(char *pkt, size_t len)
{
	(void)pkt;
	(void)len;
}

void pcapm(struct msghdr *mh)
{
	(void)mh;
}

void pcapmm(struct mmsghdr *mmh, unsigned int vlen)
{
	(void)mmh;
	(void)vlen;
}

void pcap_init(struct ctx *c, int sock_index)
{
	(void)c;
	(void)sock_index;

}
#endif

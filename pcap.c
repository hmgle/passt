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

	if (write(pcap_fd, &h, sizeof(h)) < 0 || write(pcap_fd, pkt, len) < 0)
		debug("Cannot log packet, length %u", len);
}

/**
 * pcapm() - Capture multiple frames from message header to pcap file
 * @mh:		Pointer to sendmsg() message header buffer
 */
void pcapm(struct msghdr *mh)
{
	struct pcap_pkthdr h;
	struct iovec *iov;
	struct timeval tv;
	unsigned int i;

	if (pcap_fd == -1)
		return;

	gettimeofday(&tv, NULL);
	h.tv_sec = tv.tv_sec;
	h.tv_usec = tv.tv_usec;

	for (i = 0; i < mh->msg_iovlen; i++) {
		iov = &mh->msg_iov[i];

		h.caplen = h.len = iov->iov_len - 4;

		if (write(pcap_fd, &h, sizeof(h)) < 0)
			goto fail;
		if (write(pcap_fd, (char *)iov->iov_base + 4,
			  iov->iov_len - 4) < 0)
			goto fail;
	}

	return;
fail:
	debug("Cannot log packet, length %u", iov->iov_len - 4);
}

/**
 * pcapm() - Capture multiple frames from multiple message headers to pcap file
 * @mmh:	Pointer to first sendmmsg() header
 */
void pcapmm(struct mmsghdr *mmh, unsigned int vlen)
{
	struct pcap_pkthdr h;
	struct iovec *iov;
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
			iov = &mh->msg_iov[j];

			h.caplen = h.len = iov->iov_len - 4;

			if (write(pcap_fd, &h, sizeof(h)) < 0)
				goto fail;
			if (write(pcap_fd, (char *)iov->iov_base + 4,
				  iov->iov_len - 4) < 0)
				goto fail;
		}
	}
	return;
fail:
	debug("Cannot log packet, length %u", iov->iov_len - 4);
}

/**
 * pcap_init() - Initialise pcap file
 * @c:		Execution context
 */
void pcap_init(struct ctx *c)
{
	struct timeval tv;

	if (pcap_fd != -1)
		return;

	if (!*c->pcap)
		return;

	if (*c->pcap == 1) {
		char name[] = PCAP_PREFIX PCAP_ISO8601_STR STR(UINT_MAX)
			      ".pcap";
		struct tm *tm;

		if (c->mode == MODE_PASTA)
			memcpy(name, PCAP_PREFIX_PASTA,
			       sizeof(PCAP_PREFIX_PASTA));

		gettimeofday(&tv, NULL);
		tm = localtime(&tv.tv_sec);
		strftime(name + strlen(PCAP_PREFIX),
			 sizeof(PCAP_ISO8601_STR) - 1, PCAP_ISO8601_FORMAT, tm);

		snprintf(name + strlen(PCAP_PREFIX) + strlen(PCAP_ISO8601_STR),
			 sizeof(name) - strlen(PCAP_PREFIX) -
					strlen(PCAP_ISO8601_STR),
			 "_%i.pcap", getpid());

		strncpy(c->pcap, name, PATH_MAX);
	}

	pcap_fd = open(c->pcap, O_WRONLY | O_CREAT | O_TRUNC,
		       S_IRUSR | S_IWUSR);
	if (pcap_fd == -1) {
		perror("open");
		return;
	}

	info("Saving packet capture at %s", c->pcap);

	if (write(pcap_fd, &pcap_hdr, sizeof(pcap_hdr)) < 0)
		warn("Cannot write PCAP header: %s", strerror(errno));
}

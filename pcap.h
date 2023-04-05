/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PCAP_H
#define PCAP_H

void pcap(const char *pkt, size_t len);
void pcap_multiple(const struct iovec *iov, unsigned int n, size_t offset);
void pcap_init(struct ctx *c);

#endif /* PCAP_H */

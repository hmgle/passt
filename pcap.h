/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

void pcap(char *pkt, size_t len);
void pcapm(struct msghdr *mh);
void pcapmm(struct mmsghdr *mmh, unsigned int vlen);
void pcap_init(struct ctx *c, int sock_index);

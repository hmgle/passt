/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

int ndp(struct ctx *c, struct icmp6hdr *ih, unsigned char *eh_source,
	struct in6_addr *saddr);

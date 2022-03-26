/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef NDP_H
#define NDP_H

int ndp(struct ctx *c, const struct icmp6hdr *ih,
	const unsigned char *eh_source, const struct in6_addr *saddr);

#endif /* NDP_H */

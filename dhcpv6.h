/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

int dhcpv6(struct ctx *c, struct ethhdr *eh, size_t len);
void dhcpv6_init(struct ctx *c);

/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

int dhcp(struct ctx *c, struct ethhdr *eh, size_t len);
void dhcp_init(void);

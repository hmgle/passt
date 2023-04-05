/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef DHCP_H
#define DHCP_H

int dhcp(const struct ctx *c, const struct pool *p);
void dhcp_init(void);

#endif /* DHCP_H */

/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef DHCP_H
#define DHCP_H

int dhcp(struct ctx *c, struct pool *p);
void dhcp_init(void);

#endif /* DHCP_H */

/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

int nl_sock_init(struct ctx *c);
unsigned int nl_get_ext_if(int *v4, int *v6);
void nl_route(int ns, unsigned int ifi, sa_family_t af, void *gw);
void nl_addr(int ns, unsigned int ifi, sa_family_t af,
	     void *addr, int *prefix_len, void *addr_l);
void nl_link(int ns, unsigned int ifi, void *mac, int up, int mtu);

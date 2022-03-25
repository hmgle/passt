/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef CONF_H
#define CONF_H

void conf(struct ctx *c, int argc, char **argv);
void get_bound_ports(struct ctx *c, int ns, uint8_t proto);

#endif /* CONF_H */

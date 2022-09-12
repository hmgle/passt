/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef ISOLATION_H
#define ISOLATION_H

void drop_caps(void);
void drop_root(uid_t uid, gid_t gid);
int sandbox(struct ctx *c);
void seccomp(const struct ctx *c);

#endif /* ISOLATION_H */

/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef ISOLATION_H
#define ISOLATION_H

void isolate_initial(void);
void isolate_user(uid_t uid, gid_t gid, bool use_userns, const char *userns,
		  enum passt_modes mode);
int isolate_prefork(struct ctx *c);
void isolate_postfork(const struct ctx *c);

#endif /* ISOLATION_H */

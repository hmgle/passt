/* SPDX-License-Identifier: GPL-2.0-or-later
 * Author: Hmgle <dustgle@gmail.com>
 */

#ifndef CHILD_H
#define CHILD_H

pid_t pasta_start_child(struct ctx *c, uid_t uid, gid_t gid, int argc, char *argv[]);

#endif

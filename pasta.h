/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PASTA_H
#define PASTA_H

void pasta_open_ns(struct ctx *c, const char *userns, const char *netns);
void pasta_start_ns(struct ctx *c, int argc, char *argv[]);
void pasta_ns_conf(struct ctx *c);
void pasta_child_handler(int signal);
int pasta_netns_quit_init(struct ctx *c);
void pasta_netns_quit_handler(struct ctx *c, int inotify_fd);

#endif /* PASTA_H */

/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_SPLICE_H
#define TCP_SPLICE_H

#define TCP_SPLICE_MAX_CONNS			(128 * 1024)

void tcp_sock_handler_splice(struct ctx *c, union epoll_ref ref,
			     uint32_t events);
void tcp_splice_init(struct ctx *c);
void tcp_splice_timer(struct ctx *c);
void tcp_splice_defer_handler(struct ctx *c);

#endif /* TCP_SPLICE_H */

/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_SPLICE_H
#define TCP_SPLICE_H

struct tcp_splice_conn;

void tcp_sock_handler_splice(struct ctx *c, union epoll_ref ref,
			     uint32_t events);
void tcp_splice_conn_from_sock(struct ctx *c, union epoll_ref ref,
			       struct tcp_splice_conn *conn, int s);
void tcp_splice_init(struct ctx *c);

#endif /* TCP_SPLICE_H */

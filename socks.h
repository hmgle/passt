/* SPDX-License-Identifier: GPL-2.0-or-later
 * Author: hmgle <dustgle@gmail.com>
 */

#ifndef SOCKS_H
#define SOCKS_H

#include <sys/socket.h>
#include <netdb.h>

#define satosin(x)  ((struct sockaddr_in *) &(x))
#define SOCKADDR(x) (satosin(x)->sin_addr.s_addr)
#define SOCKPORT(x) (satosin(x)->sin_port)

struct socks5_conf {
        int ai_family;
        struct sockaddr *addr;
        socklen_t addrlen;
        char *host;
        char *port;
        char *user;
        char *pwd;
};

void parse_sockaddr(const struct sockaddr *sa, char **ip_str, char **port_str);
int get_socks5_addr(const char *host, const char *port, struct sockaddr **addr,
        socklen_t *addrlen, int *ai_family);

int remote_connect(const struct sockaddr *addr, socklen_t addrlen,
        int timeout_sec);
int socks_connect(const char *host, const char *port, struct addrinfo hints,
        const char *proxyhost, const char *proxyport,
        const struct sockaddr *proxyaddr, socklen_t proxyaddrlen,
        int socksv, const char *proxyuser, const char *proxypass);

#endif

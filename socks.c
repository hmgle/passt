/*	$OpenBSD: socks.c,v 1.31 2022/06/08 20:20:26 djm Exp $	*/

/*
 * Copyright (c) 1999 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 2004, 2005 Damien Miller.  All rights reserved.
 * Copyright (c) 2023 hmgle.  All rights reserved.
 *
 * Modified by hmgle <dustgle@gmail.com> on 2023-05-11.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <resolv.h>
#include <poll.h>

#include "atomicio.h"

#define SOCKS_PORT	"1080"
#define HTTP_PROXY_PORT	"3128"
#define HTTP_MAXHDRS	64
#define SOCKS_V5	5
#define SOCKS_V4	4
#define SOCKS_NOAUTH	0
#define SOCKS_NOMETHOD	0xff
#define SOCKS_CONNECT	1
#define SOCKS_IPV4	1
#define SOCKS_DOMAIN	3
#define SOCKS_IPV6	4

int remote_connect(const struct sockaddr *addr, socklen_t addrlen,
		int timeout_sec);
int socks_connect(const char *host, const char *port, struct addrinfo hints,
    const char *proxyhost, const char *proxyport,
    const struct sockaddr *proxyaddr, socklen_t proxyaddrlen,
    int socksv, const char *proxyuser, const char *proxypass);

static int
decode_addrport(const char *h, const char *p, struct sockaddr *addr,
    socklen_t addrlen, int v4only, int numeric)
{
	int r;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	if (r != 0) {
		if (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		return (-1);
	}
	if (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return (0);
}

static int
proxy_read_line(int fd, char *buf, size_t bufsz)
{
	size_t off;

	for(off = 0;;) {
		if (off >= bufsz)
			errx(1, "proxy read too long");
		if (atomicio(read, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		if (buf[off] == '\r')
			continue;
		if (buf[off] == '\n') {
			buf[off] = '\0';
			break;
		}
		off++;
	}
	return (off);
}

/*
 * Error strings adapted from the generally accepted SOCKSv4 spec:
 *
 * http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
 */
static const char *
socks4_strerror(int e)
{
	switch (e) {
	case 90:
		return "Succeeded";
	case 91:
		return "Request rejected or failed";
	case 92:
		return "SOCKS server cannot connect to identd on the client";
	case 93:
		return "Client program and identd report different user-ids";
	default:
		return "Unknown error";
	}
}

/*
 * Error strings taken almost directly from RFC 1928.
 */
static const char *
socks5_strerror(int e)
{
	switch (e) {
	case 0:
		return "Succeeded";
	case 1:
		return "General SOCKS server failure";
	case 2:
		return "Connection not allowed by ruleset";
	case 3:
		return "Network unreachable";
	case 4:
		return "Host unreachable";
	case 5:
		return "Connection refused";
	case 6:
		return "TTL expired";
	case 7:
		return "Command not supported";
	case 8:
		return "Address type not supported";
	default:
		return "Unknown error";
	}
}

static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int encode_base_64(const char *src, char *dest, int max_len) {
	int n, i;
	size_t l;

	l = strlen(src);
	max_len = (max_len - 1) / 4;
	for(i = 0; i < max_len; i++, src += 3, l -= 3) {
		switch (l) {
			case 0:
				break;
			case 1:
				n = src[0] << 16;
				*dest++ = base64[(n >> 18) & 077];
				*dest++ = base64[(n >> 12) & 077];
				*dest++ = '=';
				*dest++ = '=';
				break;
			case 2:
				n = src[0] << 16 | src[1] << 8;
				*dest++ = base64[(n >> 18) & 077];
				*dest++ = base64[(n >> 12) & 077];
				*dest++ = base64[(n >> 6) & 077];
				*dest++ = '=';
				break;
			default:
				n = src[0] << 16 | src[1] << 8 | src[2];
				*dest++ = base64[(n >> 18) & 077];
				*dest++ = base64[(n >> 12) & 077];
				*dest++ = base64[(n >> 6) & 077];
				*dest++ = base64[n & 077];
		}
		if(l < 3)
			break;
	}
	*dest++ = 0;
	return 0;
}

int socks_connect(const char *host, const char *port,
    struct addrinfo hints __attribute__ ((__unused__)),
    const char *proxyhost __attribute__ ((__unused__)), const char *proxyport,
    const struct sockaddr *proxyaddr, socklen_t proxyaddrlen,
    int socksv, const char *proxyuser, const char *proxypass)
{
	int proxyfd, r, authretry = 0;
	size_t hlen, wlen;
	unsigned char buf[1024];
	size_t cnt;
	struct sockaddr_storage addr;
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
	in_port_t serverport;

	if (proxyport == NULL)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	if (decode_addrport("0.0.0.0", port, (struct sockaddr *)&addr,
	    sizeof(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	if (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyaddr, proxyaddrlen, 5);
	fcntl(proxyfd, F_SETFL, O_NONBLOCK);

	if (proxyfd < 0)
		return (-1);

	if (socksv == 5) {
		if (decode_addrport(host, port, (struct sockaddr *)&addr,
		    sizeof(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		if (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(read, proxyfd, buf, 2);
		if (cnt != 2) {
			perror("read");
			err(1, "read failed (%zu/3)", cnt);
			exit(errno);
		}

		if (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		switch (addr.ss_family) {
		case 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			if (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);
			memcpy(buf + 5 + hlen, &serverport, sizeof serverport);
			wlen = 7 + hlen;
			break;
		case AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, sizeof in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, sizeof in4->sin_port);
			wlen = 10;
			break;
		case AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, sizeof in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    sizeof in6->sin6_port);
			wlen = 22;
			break;
		default:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		if (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 4);
		if (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		if (buf[1] != 0) {
			errx(1, "connection failed, SOCKSv5 error: %s",
			    socks5_strerror(buf[1]));
		}
		switch (buf[3]) {
		case SOCKS_IPV4:
			cnt = atomicio(read, proxyfd, buf + 4, 6);
			if (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			break;
		case SOCKS_IPV6:
			cnt = atomicio(read, proxyfd, buf + 4, 18);
			if (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			break;
		default:
			errx(1, "connection failed, unsupported address type");
		}
	} else if (socksv == 4) {
		/* This will exit on lookup failure */
		decode_addrport(host, port, (struct sockaddr *)&addr,
		    sizeof(addr), 1, 0);

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, sizeof in4->sin_port);
		memcpy(buf + 4, &in4->sin_addr, sizeof in4->sin_addr);
		buf[8] = 0;	/* empty username */
		wlen = 9;

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		if (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 8);
		if (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		if (buf[1] != 90) {
			errx(1, "connection failed, SOCKSv4 error: %s",
			    socks4_strerror(buf[1]));
		}
	} else if (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		if (strcspn(host, "\r\n\t []") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		if (strchr(host, ':') != NULL) {
			r = snprintf((char *)buf, sizeof(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} else {
			r = snprintf((char *)buf, sizeof(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		if (r < 0 || (size_t)r >= sizeof(buf))
			errx(1, "hostname too long");
		r = strlen((char *)buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		if (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		if (authretry > 1) {
			char resp[1024];

			r = snprintf((char *)buf, sizeof(buf), "%s:%s",
			    proxyuser, proxypass);
			if (r == -1 || (size_t)r >= sizeof(buf) ||
			    encode_base_64((char *)buf, resp, sizeof(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf((char *)buf, sizeof(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			if (r < 0 || (size_t)r >= sizeof(buf))
				errx(1, "Proxy auth response too long");
			r = strlen((char *)buf);
			if ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
			memset(buf, 0, sizeof buf);
		}

		/* Terminate headers */
		if ((cnt = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (%zu/2)", cnt);

		/* Read status reply */
		proxy_read_line(proxyfd, (char *)buf, sizeof(buf));
		if (proxyuser != NULL &&
		    (strncmp((char *)buf, "HTTP/1.0 407 ", 12) == 0 ||
		    strncmp((char *)buf, "HTTP/1.1 407 ", 12) == 0)) {
			if (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			goto again;
		} else if (strncmp((char *)buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp((char *)buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		for (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_line(proxyfd, (char *)buf, sizeof(buf));
			if (*buf == '\0')
				break;
		}
		if (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} else
		errx(1, "Unknown proxy protocol %d", socksv);

	return (proxyfd);
}

/**
 * remote_connect() - connect remote
 *
 * #syscalls poll
 */
int remote_connect(const struct sockaddr *addr, socklen_t addrlen,
		int timeout_sec)
{
	int flags, ret;
	struct pollfd fds[1];
	int sockfd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	flags = fcntl(sockfd, F_GETFL, 0);
	if ((flags & O_NONBLOCK) == 0)
		fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	ret = connect(sockfd, addr, addrlen);
	perror("connect");
	if (ret == -1 && errno == EINPROGRESS) {
		fds[0].fd = sockfd;
		fds[0].events = POLLOUT;
		ret = poll(fds, 1, timeout_sec * 1000);
		if (ret == 1) {
			int err = 0;
			socklen_t len = sizeof(err);
			ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len);
			if (ret < 0) {
				perror("getsockopt");
				goto end;
			}
			if (err) {
				errno = err;
				ret = -1;
				goto end;
			}
		} else if (ret < 0) {
			perror("poll");
			goto end;
		} else if (ret == 0) {
			err(1, "connect timeout");
			errno = ETIMEDOUT;
			return -1;
		}

	}
end:
	if (ret < 0) {
		close(sockfd);
		return ret;
	}
	if ((flags & O_NONBLOCK) == 0)
		fcntl(sockfd, F_SETFL, flags);
	return sockfd;
}

int get_proxy_addr(const char *host, const char *port, struct sockaddr **addr,
		socklen_t *addrlen, int *ai_family)
{
	int ret;
	struct addrinfo *res;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, port, &hints, &res);
	if (ret) {
		perror("getaddrinfo");
		return ret;
	}
	*ai_family = res->ai_family;
	*addrlen = res->ai_addrlen;
	*addr = malloc(res->ai_addrlen);
	memcpy(*addr, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);
	return ret;
}

void parse_sockaddr(const struct sockaddr *sa, char **ip_str, char **port_str)
{
	char ip[INET6_ADDRSTRLEN];
	int port;
	void *addr;

	if(sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		addr = &(sin->sin_addr);
		port = ntohs(sin->sin_port);
	} else if(sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		addr = &(sin6->sin6_addr);
		port = ntohs(sin6->sin6_port);
	} else {
		warn("Unsupported address family");
		exit(EXIT_FAILURE);
	}

	if(inet_ntop(sa->sa_family, addr, ip, sizeof(ip)) == NULL) {
		perror("inet_ntop");
		exit(EXIT_FAILURE);
	}

	if((*port_str = calloc(1, 6)) == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	snprintf(*port_str, 6, "%d", port);

	*ip_str = strdup(ip);
}

// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * log.c - Logging functions
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "log.h"

/* For __openlog() and __setlogmask() wrappers, and passt_vsyslog() */
static int	log_mask;
static int	log_sock = -1;
static char	log_ident[BUFSIZ];
static int	log_opt;
static time_t	log_debug_start;
int		log_trace;

#define logfn(name, level)						\
void name(const char *format, ...) {					\
	struct timespec tp;						\
	va_list args;							\
									\
	if (setlogmask(0) & LOG_MASK(LOG_DEBUG)) {			\
		clock_gettime(CLOCK_REALTIME, &tp);			\
		fprintf(stderr, "%li.%04li: ",				\
			tp.tv_sec - log_debug_start,			\
			tp.tv_nsec / (100L * 1000));			\
	} else {							\
		va_start(args, format);					\
		passt_vsyslog(level, format, args);			\
		va_end(args);						\
	}								\
									\
	if (setlogmask(0) & LOG_MASK(LOG_DEBUG) ||			\
	    setlogmask(0) == LOG_MASK(LOG_EMERG)) {			\
		va_start(args, format);					\
		(void)vfprintf(stderr, format, args); 			\
		va_end(args);						\
		if (format[strlen(format)] != '\n')			\
			fprintf(stderr, "\n");				\
	}								\
}

logfn(err,   LOG_ERR)
logfn(warn,  LOG_WARNING)
logfn(info,  LOG_INFO)
logfn(debug, LOG_DEBUG)

void trace_init(int enable)
{
	log_trace = enable;
}

/**
 * __openlog() - Non-optional openlog() wrapper, to allow custom vsyslog()
 * @ident:	openlog() identity (program name)
 * @option:	openlog() options
 * @facility:	openlog() facility (LOG_DAEMON)
 */
void __openlog(const char *ident, int option, int facility)
{
	struct timespec tp;

	clock_gettime(CLOCK_REALTIME, &tp);
	log_debug_start = tp.tv_sec;

	if (log_sock < 0) {
		struct sockaddr_un a = { .sun_family = AF_UNIX, };

		log_sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (log_sock < 0)
			return;

		strncpy(a.sun_path, _PATH_LOG, sizeof(a.sun_path));
		if (connect(log_sock, (const struct sockaddr *)&a, sizeof(a))) {
			close(log_sock);
			log_sock = -1;
			return;
		}
	}

	log_mask |= facility;
	strncpy(log_ident, ident, sizeof(log_ident) - 1);
	log_opt = option;

	openlog(ident, option, facility);
}

/**
 * __setlogmask() - setlogmask() wrapper, to allow custom vsyslog()
 * @mask:	Same as setlogmask() mask
 */
void __setlogmask(int mask)
{
	log_mask = mask;
	setlogmask(mask);
}

/**
 * passt_vsyslog() - vsyslog() implementation not using heap memory
 * @pri:	Facility and level map, same as priority for vsyslog()
 * @format:	Same as vsyslog() format
 * @ap:		Same as vsyslog() ap
 */
void passt_vsyslog(int pri, const char *format, va_list ap)
{
	char buf[BUFSIZ];
	int n;

	if (!(LOG_MASK(LOG_PRI(pri)) & log_mask))
		return;

	/* Send without name and timestamp, the system logger should add them */
	n = snprintf(buf, BUFSIZ, "<%i> ", pri);

	n += vsnprintf(buf + n, BUFSIZ - n, format, ap);

	if (format[strlen(format)] != '\n')
		n += snprintf(buf + n, BUFSIZ - n, "\n");

	if (log_opt & LOG_PERROR)
		fprintf(stderr, "%s", buf + sizeof("<0>"));

	if (send(log_sock, buf, n, 0) != n)
		fprintf(stderr, "Failed to send %i bytes to syslog\n", n);
}

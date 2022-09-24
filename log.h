/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef LOG_H
#define LOG_H

void err(const char *format, ...);
void warn(const char *format, ...);
void info(const char *format, ...);
void debug(const char *format, ...);

extern int log_trace;
void trace_init(int enable);
#define trace(format, ...)						\
	do {								\
		if (log_trace)						\
			debug(format, ##__VA_ARGS__);			\
	} while (0)

void __openlog(const char *ident, int option, int facility);
void passt_vsyslog(int pri, const char *format, va_list ap);
void __setlogmask(int mask);

#endif /* LOG_H */

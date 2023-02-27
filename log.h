/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef LOG_H
#define LOG_H

#define LOGFILE_SIZE_DEFAULT		(1024 * 1024UL)
#define LOGFILE_CUT_RATIO		30	/* When full, cut ~30% size */
#define LOGFILE_SIZE_MIN		(5UL * MAX(BUFSIZ, PAGE_SIZE))

void err(const char *format, ...);
void warn(const char *format, ...);
void info(const char *format, ...);
void debug(const char *format, ...);

#define die(...)							\
	do {								\
		err(__VA_ARGS__);					\
		exit(EXIT_FAILURE);					\
	} while (0)

extern int log_trace;
void trace_init(int enable);
#define trace(...)							\
	do {								\
		if (log_trace)						\
			debug(__VA_ARGS__);				\
	} while (0)

void __openlog(const char *ident, int option, int facility);
void logfile_init(const char *name, const char *path, size_t size);
void passt_vsyslog(int pri, const char *format, va_list ap);
void logfile_write(int pri, const char *format, va_list ap);
void __setlogmask(int mask);

#endif /* LOG_H */

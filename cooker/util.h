/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UTIL_H
#define UTIL_H

#define BIT(n)			(1UL << (n))

void err(const char *format, ...);
void info(const char *format, ...);
void debug(const char *format, ...);

#define die(...)							\
	do {								\
		fprintf(stderr, "%s:%i: ", __FILE__, __LINE__);		\
		err(__VA_ARGS__);					\
		exit(EXIT_FAILURE);					\
	} while (0)

#endif /* UTIL_H */

// SPDX-License-Identifier: AGPL-3.0-or-later

/* SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * build.c - Build BPF program and transformation table blobs
 *
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

struct syscall_numbers {
	char name[1024];
	long number;
};

enum transform {
	NONE,
	FD1_UNIX,
	FDRET_SRC,
	DEV_CHECK,
};

#include "filter.h"
#include "numbers.h"

struct table {
	enum transform type;
	long number;

	char arg[6][1024];
};

static struct table t[16];

int main(void)
{
	struct table *tp = t;
	char buf[BUFSIZ];
	FILE *fp;
	int fd;

	fd = open(BUILD_BPF_OUT, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  S_IRUSR | S_IWUSR);
	write(fd, BUILD_PROFILE, sizeof(BUILD_PROFILE));
	close(fd);

	fp = fopen(BUILD_IN, "r");
	while (fgets(buf, BUFSIZ, fp)) {
		char name[1024];
		char type[1024];
		unsigned i;

		if (*buf == '\n' || *buf == '#')
			continue;
		if (sscanf(buf, "%s %s " /* syscall, type */
				"%s %s %s %s %s %s", name, type,
				tp->arg[0], tp->arg[1], tp->arg[2],
				tp->arg[3], tp->arg[4], tp->arg[5]) < 3)
			continue;

		for (i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
			if (!strcmp(name, numbers[i].name))
				break;
		}

		if (i == sizeof(numbers))
			continue;

		if (!strcmp(type, "fd1_unix"))
			tp->type = 1;
		else if (!strcmp(type, "fdret_src"))
			tp->type = 2;
		else if (!strcmp(type, "dev_check"))
			tp->type = 3;
		else
			continue;

		tp->number = numbers[i].number;

		tp++;
	}
	fclose(fp);

	fd = open(BUILD_TRANSFORM_OUT,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR);

	write(fd, t, sizeof(t));
	close(fd);

	return 0;
}

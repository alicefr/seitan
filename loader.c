// SPDX-License-Identifier: AGPL-3.0-or-later

/* SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * loader.c - Load BPF program and execute binary
 *
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

extern char **environ;

static char *qemu_names[] = {
	"kvm",
	"qemu-kvm",
#ifdef ARCH
	( "qemu-system-" ARCH ),
#endif
	"/usr/libexec/qemu-kvm",
	NULL,
};

/**
 * usage() - Print usage and exit
 */
void usage(void)
{
	fprintf(stderr, "Usage: seitan-loader [QEMU_ARG]...\n");
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(__NR_seccomp, operation, flags, args);
}

/**
 * main() - Entry point
 * @argc:	Argument count
 * @argv:	qemu arguments
 *
 * Return: 0 once interrupted, non-zero on failure
 */
int main(int argc, char **argv)
{
	int fd = open("bpf.out", O_CLOEXEC | O_RDONLY);
	struct sock_filter filter[1024];
	struct sock_fprog prog;
	char **name;
	size_t n;

	(void)argc;

	n = read(fd, filter, sizeof(filter));
	close(fd);

	prog.filter = filter;
	prog.len = (unsigned short)(n / sizeof(filter[0]));
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	fd = seccomp(SECCOMP_SET_MODE_FILTER,
		     SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);

	connect(0, NULL, 0);	/* Wait for seitan to unblock this */

	for (name = qemu_names; *name; name++) {
		argv[0] = *name;
		execvpe(*name, argv, environ);
		if (errno != ENOENT) {
			perror("execvpe");
			usage();
		}
	}

	perror("execvpe");
	return EXIT_FAILURE;
}

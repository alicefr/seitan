// SPDX-License-Identifier: AGPL-3.0-or-later

/* SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * src/eater/eater.c - Load BPF program and execute binary
 *
 * Copyright (c) 2022 Red Hat GmbH
 * Authors: Stefano Brivio <sbrivio@redhat.com>, Alice Frosi <afrosi@redhat.com>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <dirent.h>
#include <sys/stat.h>

#include "common.h"
static struct option options[] = {
	{ "input", required_argument, NULL, 'i' },
	{ 0, 0, 0, 0 },
};

extern char **environ;

/* Eater options */
struct arguments {
	char *input_file;
	unsigned int program_index;
};

static void usage()
{
	printf("seitan-eater: installer for the BPF filter before launching the process\n"
	       "Example: seitan-eater: setain-eater -i <input file> -- program args1 args2...;\n"
	       "Usage:\n"
	       "\t-i, --input:\tAction input file\n");
	exit(EXIT_FAILURE);
}

static void parse(int argc, char **argv, struct arguments *arguments)
{
	int index = 0;
	int oc;

	arguments->program_index = 0;
	while ((oc = getopt_long(argc, argv, "i:", options, &index)) != -1) {
		switch (oc) {
		case 'i':
			arguments->input_file = optarg;
			break;
		case '?':
			fprintf(stderr, "unknow option %c\n", optopt);
			usage();
		}
	}
	arguments->program_index = optind;
	if (arguments->input_file == NULL) {
		fprintf(stderr, "missing input file\n");
		usage();
	}
	if (strcmp(argv[optind - 1], "--") != 0) {
		fprintf(stderr, "missing program\n");
		usage();
	}
}

static void signal_handler(__attribute__((unused)) int s)
{
}

/**
 * main() - Entry point
 * @argc:	Argument count
 * @argv:	Seitan-eater and program arguments
 *
 * Return: 0 once interrupted, non-zero on failure
 */
int main(int argc, char **argv)
{
	struct sock_filter filter[1024];
	struct arguments arguments;
	struct sigaction act;
	int fd, flags;
	size_t n;

	parse(argc, argv, &arguments);
	fd = open(arguments.input_file, O_CLOEXEC | O_RDONLY);
	n = read(fd, filter, sizeof(filter));
	close(fd);

	install_filter(filter, (unsigned short)(n / sizeof(filter[0])));
	/*
	 * close-on-exec flag is set for the file descriptor by seccomp.
	 * We want to preserve the fd on the exec in this way we are able
	 * to easly find the notifier fd if seitan restarts.
	 */
	fd = find_fd_seccomp_notifier("/proc/self/fd");
	flags = fcntl(fd, F_GETFD);
	if (fcntl(fd, F_SETFD, flags & !FD_CLOEXEC) < 0) {
		perror("fcntl");
		exit(EXIT_FAILURE);
	}
	act.sa_handler = signal_handler;
	sigaction(SIGCONT, &act, NULL);
	pause();

	execvpe(argv[arguments.program_index], &argv[arguments.program_index],
		environ);
	if (errno != ENOENT) {
		perror("execvpe");
		exit(EXIT_FAILURE);
	}
	close(fd);
	return EXIT_FAILURE;
}

// SPDX-License-Identifier: AGPL-3.0-or-later

/* SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * eater.c - Load BPF program and execute binary
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
#include <argp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <signal.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <dirent.h>
#include <sys/stat.h>

#include "common.h"

extern char **environ;

static char doc[] =
	"Usage: seitan-eater: setain-eater -i <input file> -- program args1 args2...";

/* Eater options */
static struct argp_option options[] = { { "input", 'i', "FILE", 0,
					  "BPF filter input file", 0 },
					{ 0 } };

struct arguments {
	char *input_file;
	unsigned int program_index;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	if (state->quoted == 0)
		arguments->program_index = state->next + 1;
	switch (key) {
	case 'i':
		if (state->quoted == 0)
			arguments->input_file = arg;
		break;
	case ARGP_KEY_END:
		if (arguments->input_file == NULL)
			argp_error(state, "missing input file");
		if (state->argv[arguments->program_index] == NULL)
			argp_error(state, "missing program");
		break;
	}

	return 0;
}

static struct argp argp = { .options = options,
			    .parser = parse_opt,
			    .args_doc = NULL,
			    .doc = doc,
			    .children = NULL,
			    .help_filter = NULL,
			    .argp_domain = NULL };

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(__NR_seccomp, operation, flags, args);
}

static void signal_handler(__attribute__((unused))int s){}

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
	struct sock_fprog prog;
	struct sigaction act;
	size_t n;
	int fd, flags;

	argp_parse(&argp, argc, argv, 0, 0, &arguments);
	fd = open(arguments.input_file, O_CLOEXEC | O_RDONLY);
	n = read(fd, filter, sizeof(filter));
	close(fd);

	prog.filter = filter;
	prog.len = (unsigned short)(n / sizeof(filter[0]));
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("prctl");
		exit(EXIT_FAILURE);
	}
	if (seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
					&prog) < 0) {
		perror("seccomp");
		exit(EXIT_FAILURE);
	}
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

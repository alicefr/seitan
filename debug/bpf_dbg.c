/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <unistd.h>

#include "disasm.h"

int main(int argc, char **argv)
{
	struct sock_filter *filter;
	size_t fd, n;

	if (argc < 2) {
		perror("missing input file");
		exit(EXIT_FAILURE);
	}
	filter = calloc(SIZE_FILTER, sizeof(struct sock_filter));
	fd = open(argv[1], O_CLOEXEC | O_RDONLY);

	n = read(fd, filter, sizeof(struct sock_filter) * SIZE_FILTER);
	close(fd);
	printf("Read %ld entries\n", n / sizeof(struct sock_filter));
	bpf_disasm_all(filter, n / sizeof(struct sock_filter));
	free(filter);
	return 0;
}

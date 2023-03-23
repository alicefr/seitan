#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "filter.h"

struct bpf_call calls[] = {
	{
		.name = "connect",
		.args = { 0, 111, 0, 0, 0, 0 },
		.check_arg = { false, false, false, false, false, false },
	},
};

int main(int argc, char **argv)
{
	int ret;
	if (argc < 2) {
		perror("missing input file");
		exit(EXIT_FAILURE);
	}
	ret = convert_bpf(argv[1], calls, sizeof(calls) / sizeof(calls[0]),
			  true);
	if (ret < 0) {
		perror("converting bpf program");
		exit(EXIT_FAILURE);
	}
	return 0;
}

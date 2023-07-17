// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/main.c - Entry point of seitan-cooker, the gluten (bytecode) generator
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * 	   Alice Frosi <afrosi@redhat.com>
 */

#define _GNU_SOURCE
#include <getopt.h>

#include "parson.h"
#include "cooker.h"
#include "gluten.h"
#include "parse.h"
#include "filter.h"

/* Cooker options */
static struct option options[] = {
	{ "input", required_argument, NULL, 'i' },
	{ "gluten", required_argument, NULL, 'g' },
	{ "filter", required_argument, NULL, 'f' },
	{ "scmp-profile", required_argument, NULL, 'p' },
};

struct arguments {
	char *input_file;
	char *gluten_file;
	char *filter_file;
	char *scmp_profile_file;
};

static void usage()
{
	printf("seitan-cooker: generate the BPF filters or seccomp profile and the action byte code for seitan\n"
               "Example:  setain-cooker -i <input file> -g <gluten_file> -f <filter_file>\n"
               "Usage:\n"
               "\t-i, --input:\tJSON input file\n"
               "\t-g, --gluten:\tBytecode file for seitan action\n"
               "\t-f, --filter:\tBPF filter file (cannot be used together with scmp-profile)\n"
               "\t-p, --scmp-profile:\tSeccomp profile file (cannot be used together with filter)\n");
        exit(EXIT_FAILURE);
}

static void parse(int argc, char **argv, struct arguments *arguments)
{
	int option_index = 0;
	int oc;
	if (arguments == NULL)
		usage();
	while ((oc = getopt_long(argc, argv, ":i:g:f:p:", options,
				 &option_index)) != -1) {
		switch (oc) {
		case 'i':
			arguments->input_file = optarg;
			break;
		case 'g':
			arguments->gluten_file = optarg;
			break;
		case 'f':
			arguments->filter_file = optarg;
			break;
		case 'p':
			arguments->scmp_profile_file = optarg;
			break;
		default:
			usage();
		}
	}
	if (arguments->input_file == NULL) {
		err("missing input file");
		usage();
	}
	if (arguments->filter_file != NULL &&
	    arguments->scmp_profile_file != NULL) {
		err("the filter and scmp-profile options cannot be used together");
		usage();
	}
	if (arguments->filter_file == NULL &&
	    arguments->scmp_profile_file == NULL) {
		err("select one of the options between filter and scmp-profile");
		usage();
	}
	if (arguments->gluten_file == NULL) {
		err("missing gluten file");
		usage();
	}
}

/**
 * main() - Entry point for cooker
 * @argc:	Argument count
 * @argv:	Options: input filename, output filename
 *
 * Return: zero on success, doesn't return on failure
 */
int main(int argc, char **argv)
{
	struct arguments arguments = { 0 };
	struct gluten_ctx g = { 0 };

	parse(argc, argv, &arguments);

	gluten_init(&g);

	parse_file(&g, arguments.input_file);

	gluten_write(&g, arguments.gluten_file);
	filter_write(arguments.filter_file);

	return 0;
}

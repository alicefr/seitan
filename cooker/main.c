// SPDX-License-Identifier: GPL-3.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/main.c - Entry point of seitan-cooker, the gluten (bytecode) generator
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "parson.h"
#include "cooker.h"
#include "gluten.h"
#include "parse.h"
#include "filter.h"

/**
 * main() - Entry point for cooker
 * @argc:	Argument count
 * @argv:	Options: input filename, output filename
 *
 * Return: zero on success, doesn't return on failure
 */
int main(int argc, char **argv)
{
	struct gluten_ctx g = { 0 };

	/* TODO: Options and usage */
	if (argc != 4)
		die("%s INPUT GLUTEN BPF", argv[0]);

	gluten_init(&g);

	parse_file(&g, argv[1]);

	gluten_write(&g, argv[2]);
	filter_write(argv[3]);

	return 0;
}

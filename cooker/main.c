// SPDX-License-Identifier: GPL-3.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/main.c - Entry point of seitan-cooker, the gluten (bytecode) generator
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "cooker.h"
#include "gluten.h"
#include "parse.h"

int main(int argc, char **argv)
{
	struct gluten_ctx g = { 0 };

	/* TODO: Options and usage */
	(void)argc;
	(void)argv;

	gluten_init(&g);

	parse_file(&g, argv[1]);

	return 0;
}

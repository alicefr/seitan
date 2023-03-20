// SPDX-License-Identifier: GPL-3.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/gluten.c - gluten (bytecode) file and layout functions
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "cooker.h"
#include "gluten.h"
#include "util.h"

#define GLUTEN_INST_SIZE		BUFSIZ
#define GLUTEN_DATA_SIZE		BUFSIZ

static char gluten[GLUTEN_INST_SIZE + GLUTEN_DATA_SIZE];

static size_t gluten_arg_storage[ARG_TYPE_COUNT] = {
	[ARG_INT]	= sizeof(int),
	[ARG_INTMASK]	= sizeof(int),
};

int gluten_alloc(struct gluten_ctx *g, size_t size)
{
	debug("   allocating %lu at offset %i", size, g->sp);
	if ((g->sp += size) >= GLUTEN_DATA_SIZE)
		die("Temporary data size exceeded");

	return g->sp - size;
}

int gluten_alloc_type(struct gluten_ctx *g, enum arg_type type)
{
	return gluten_alloc(g, gluten_arg_storage[type]);
}

int gluten_init(struct gluten_ctx *g)
{
	g->gluten = gluten;

	return 0;
}

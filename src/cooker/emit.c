// SPDX-License-Identifier: GPL-3.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/emit.c - Generate gluten (bytecode) instructions
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "cooker.h"
#include "gluten.h"
#include "util.h"

int emit_nr(struct gluten_ctx *g, long number)
{
	debug("   %i: OP_NR %li, < >", g->ip++, number);

	return 0;
}

int emit_load(struct gluten_ctx *g, int offset, int index, size_t len)
{
	debug("   %i: OP_LOAD #%i < %i (%lu)", g->ip++, offset, index, len);

	return 0;
}

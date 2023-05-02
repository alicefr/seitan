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

size_t gluten_size[TYPE_COUNT] = {
	[INT]		= sizeof(int),
	[INTMASK]	= sizeof(int),
	[INTFLAGS]	= sizeof(int),

	[U32]		= sizeof(uint32_t),
	[U32MASK]	= sizeof(uint32_t),
	[U32FLAGS]	= sizeof(uint32_t),

	[LONG]		= sizeof(long),
	[LONGMASK]	= sizeof(long),
	[LONGFLAGS]	= sizeof(long),

	[PID]		= sizeof(pid_t),
	[PORT]		= sizeof(in_port_t),
	[IPV4]		= sizeof(struct in_addr),
	[IPV6]		= sizeof(struct in6_addr),

};

struct gluten_offset gluten_alloc(struct gluten_ctx *g, size_t size)
{
	struct gluten_offset ret = g->dp;

	debug("   allocating %lu at offset %i", size, g->dp.offset);
	if ((g->dp.offset += size) >= DATA_SIZE)
		die("Temporary data size exceeded");

	return ret;
}

struct gluten_offset gluten_alloc_type(struct gluten_ctx *g, enum type type)
{
	return gluten_alloc(g, gluten_size[type]);
}

void gluten_init(struct gluten_ctx *g)
{
	(void)g;

	g->ip.type = g->lr.type = OFFSET_INSTRUCTION;
	g->dp.type = OFFSET_DATA;
	g->cp.type = OFFSET_RO_DATA;
}

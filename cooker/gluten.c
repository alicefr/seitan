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

const char *jump_name[JUMP_COUNT] = { "next block", "next match", "end" };

/**
 * gluten_alloc() - Allocate in temporary (seitan read-write) data area
 * @g:		gluten context
 * @size:	Bytes to allocate
 *
 * Return: offset to allocated area
 */
struct gluten_offset gluten_alloc(struct gluten_ctx *g, size_t size)
{
	struct gluten_offset ret = g->dp;

	debug("   allocating %lu at offset %i", size, g->dp.offset);
	if ((g->dp.offset += size) >= DATA_SIZE)
		die("Temporary data size exceeded");

	return ret;
}

/**
 * gluten_alloc() - Allocate storage for given type in temporary data area
 * @g:		gluten context
 * @type:	Data type
 *
 * Return: offset to allocated area
 */
struct gluten_offset gluten_alloc_type(struct gluten_ctx *g, enum type type)
{
	return gluten_alloc(g, gluten_size[type]);
}

void gluten_add_tag(struct gluten_ctx *g, const char *name,
		    struct gluten_offset offset)
{
	int i;

	for (i = 0; i < TAGS_MAX && g->tags[i].name; i++);
	if (i == TAGS_MAX)
		die("Too many tags");

	g->tags[i].name = name;
	g->tags[i].offset = offset;

	debug("   tag '%s' now refers to %s at %i",
	      name, gluten_offset_name[offset.type], offset.offset);
}

/**
 * gluten_init() - Initialise gluten structures and layout
 * @g:		gluten context
 */
void gluten_init(struct gluten_ctx *g)
{
	g->ip.type = g->lr.type = g->mr.type = OFFSET_INSTRUCTION;
	g->ip.offset = g->lr.offset = g->mr.offset = 0;
	g->dp.type = OFFSET_DATA;
	g->cp.type = OFFSET_RO_DATA;
}

void gluten_write(struct gluten_ctx *g, const char *path)
{
	ssize_t n;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  S_IRUSR | S_IWUSR);

	if ((n = write(fd, &g->g, sizeof(g->g))) == -1)
		die("Failed to write gluten: %s", strerror(errno));

	if (n != sizeof(g->g))
		die("Failed to write %i bytes of gluten", sizeof(g->g) - n);

	close(fd);
}

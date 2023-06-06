// SPDX-License-Identifier: GPL-2.0-or-later

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
	[USHORT]	= sizeof(unsigned short),
	[INT]		= sizeof(int),
	[U32]		= sizeof(uint32_t),
	[U64]		= sizeof(uint64_t),
	[LONG]		= sizeof(long),

	[PID]		= sizeof(pid_t),
	[PORT]		= sizeof(in_port_t),
	[IPV4]		= sizeof(struct in_addr),
	[IPV6]		= sizeof(struct in6_addr),

	[GNU_DEV_MAJOR]	= sizeof(unsigned long long int),
	[GNU_DEV_MINOR]	= sizeof(unsigned long long int),
};

const char *jump_name[JUMP_COUNT] = { "next block", "next match", "next action",
				      "end" };

/**
 * gluten_rw_alloc() - Allocate in temporary (seitan read-write) data area
 * @g:		gluten context
 * @size:	Bytes to allocate
 *
 * Return: offset to allocated area
 */
struct gluten_offset gluten_rw_alloc(struct gluten_ctx *g, size_t size)
{
	struct gluten_offset ret = g->dp;

	debug("   allocating %lu at read-write offset %i", size, g->dp.offset);
	if ((g->dp.offset += size) >= DATA_SIZE)
		die("Temporary data size exceeded");

	return ret;
}

/**
 * gluten_rw_alloc_type() - Allocate storage for given type in temporary area
 * @g:		gluten context
 * @type:	Data type
 *
 * Return: offset to allocated area
 */
struct gluten_offset gluten_rw_alloc_type(struct gluten_ctx *g, enum type type)
{
	return gluten_rw_alloc(g, gluten_size[type]);
}

/**
 * gluten_ro_alloc() - Allocate in read-only data area
 * @g:		gluten context
 * @size:	Bytes to allocate
 *
 * Return: offset to allocated area
 */
struct gluten_offset gluten_ro_alloc(struct gluten_ctx *g, size_t size)
{
	struct gluten_offset ret = g->cp;

	debug("   allocating %lu at read-only offset %i", size, g->cp.offset);
	if ((g->cp.offset += size) >= RO_DATA_SIZE)
		die("Read-only data size exceeded");

	return ret;
}

/**
 * gluten_ro_alloc_type() - Allocate storage for given type in read-only area
 * @g:		gluten context
 * @type:	Data type
 *
 * Return: offset to allocated area
 */
struct gluten_offset gluten_ro_alloc_type(struct gluten_ctx *g, enum type type)
{
	return gluten_ro_alloc(g, gluten_size[type]);
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

void gluten_add_tag_post(struct gluten_ctx *g, const char *name,
			 struct gluten_offset offset)
{
	/* TODO: Mark as invalid for current rule */
	gluten_add_tag(g, name, offset);
}

struct gluten_offset gluten_get_tag(struct gluten_ctx *g, const char *name)
{
	int i;

	for (i = 0; i < TAGS_MAX && g->tags[i].name; i++) {
		if (!strcmp(g->tags[i].name, name))
			return g->tags[i].offset;
	}

	die("   tag '%s' not found", name);
	return g->tags[0].offset;	/* Pro forma, not actually happening */
}

void gluten_add_attr(struct gluten_ctx *g, enum attr_type type, intptr_t id,
		     union value v)
{
	int i;

	for (i = 0; i < ATTRS_MAX && g->attrs[i].id; i++);
	if (i == ATTRS_MAX)
		die("Too many attributes");

	g->attrs[i].type = type;
	g->attrs[i].id = id;
	g->attrs[i].v = v;

	debug("   attribute '%p' set", id);
}

union value gluten_get_attr(struct gluten_ctx *g, enum attr_type type,
			    intptr_t id)
{
	int i;

	for (i = 0; i < ATTRS_MAX && g->attrs[i].type; i++) {
		if (g->attrs[i].type == type && g->attrs[i].id == id)
			return g->attrs[i].v;
	}

	die("   attribute '%p' not found", id);
	return g->attrs[0].v;		/* Pro forma, not actually happening */
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

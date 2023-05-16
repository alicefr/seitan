// SPDX-License-Identifier: GPL-3.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/emit.c - Generate gluten (bytecode) instructions and read-only data
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "cooker.h"
#include "gluten.h"
#include "util.h"
#include "emit.h"

static const char *type_str[] = {
	"UNDEF", "NONE",
	"INT",  "INTMASK",  "INTFLAGS",
	"U32",  "U32MASK",  "U32FLAGS",
	"U64",  "U64MASK",  "U64FLAGS",
	"LONG", "LONGMASK", "LONGFLAGS",
	"STRING",
	"STRUCT", "SELECT",
	"PID",
	"PORT", "IPV4", "IPV6",
	"FDPATH",
	NULL
};

static const char *cmp_type_str[] = {
	"EQ", "NE", "GT", "GE", "LT", "LE", NULL
};

/**
 * emit_nr() - Emit OP_NR instruction: jump on syscall mismatch
 * @g:		gluten context
 * @number:	Pointer to system call number
 */
void emit_nr(struct gluten_ctx *g, struct gluten_offset number)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_nr *nr = &op->op.nr;

	op->type = OP_NR;

	nr->nr = number;
	nr->no_match.type = OFFSET_INSTRUCTION;
	nr->no_match.offset = JUMP_NEXT_BLOCK;

	debug("   %i: OP_NR: if syscall number is not %li, jump to %s",
	      g->ip.offset, number, jump_name[nr->no_match.offset]);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_load() - Emit OP_LOAD instruction: dereference and copy syscall argument
 * @g:		gluten context
 * @dst:	gluten destination to copy dereferenced data
 * @index:	Index of system call argument
 * @len:	Length of data item pointed by reference
 */
void emit_load(struct gluten_ctx *g, struct gluten_offset dst,
	       int index, size_t len)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_load *load = &op->op.load;

	op->type = OP_LOAD;

	load->src.type = OFFSET_SECCOMP_DATA;
	load->src.offset = index;

	load->dst = dst;

	debug("   %i: OP_LOAD: #%i < args[%i] (size: %lu)",
	      g->ip.offset, dst.offset, index, len);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_cmp(): Emit OP_CMP instruction: compare data from two offsets
 * @g:		gluten context
 * @cmp_type:	Type of comparison
 * @x:		gluten pointer to first operand of comparison
 * @y:		gluten pointer to second operand of comparison
 * @size:	Size of comparison
 * @jmp:	Jump direction if comparison is true
 */
void emit_cmp(struct gluten_ctx *g, enum op_cmp_type cmp_type,
	      struct gluten_offset x, struct gluten_offset y, size_t size,
	      enum jump_type jmp)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_cmp *cmp = &op->op.cmp;

	op->type = OP_CMP;

	cmp->x = x;
	cmp->y = y;
	cmp->size = size;
	cmp->cmp = cmp_type;
	cmp->jmp.type = OFFSET_INSTRUCTION;
	cmp->jmp.offset = jmp;

	debug("   %i: OP_CMP: if %s: #%lu %s (size: %lu) %s: #%lu, jump to %s",
	      g->ip.offset,
	      gluten_offset_name[x.type], x.offset,
	      cmp_type_str[cmp_type], size,
	      gluten_offset_name[y.type], y.offset,
	      jump_name[jmp]);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_cmp_field() - Emit OP_CMP for a given field type
 * @g:		gluten context
 * @cmp:	Type of comparison
 * @field:	Description of field from system call model
 * @x:		gluten pointer to first operand of comparison
 * @y:		gluten pointer to second operand of comparison
 * @jmp:	Jump direction if comparison is true
 */
void emit_cmp_field(struct gluten_ctx *g, enum op_cmp_type cmp,
		    struct field *field,
		    struct gluten_offset x, struct gluten_offset y,
		    enum jump_type jmp)
{
	emit_cmp(g, cmp, x, y,
		 field->strlen ? field->strlen : gluten_size[field->type],
		 jmp);
}

struct gluten_offset emit_data(struct gluten_ctx *g, enum type type,
			       size_t str_len, union value *value)
{
	void *p = gluten_ptr(&g->g, g->cp);
	struct gluten_offset ret = g->cp;

	switch (type) {
	case INT:
		if (g->cp.offset + sizeof(int) > RO_DATA_SIZE)
			die("   Read-only data section exceeded");

		*(int *)p = value->v_int;
		debug("   C#%i: (%s) %i", g->cp.offset, type_str[type],
		      value->v_int);

		g->cp.offset += sizeof(int);
		break;
	case STRING:
		if (g->cp.offset + str_len > RO_DATA_SIZE)
			die("   Read-only data section exceeded");

		strncpy(p, value->v_str, str_len);
		debug("   C#%i: (%s:%i) %s", g->cp.offset, type_str[type],
		      str_len, value->v_str);

		g->cp.offset += str_len;
		break;
	default:
		;
	}

	return ret;
}

static void gluten_link(struct gluten_ctx *g, enum jump_type type,
			struct op *start)
{
	struct gluten_offset *jmp;
	struct op *op;

	for (op = (struct op *)start; op->type; op++) {
		switch (op->type) {
		case OP_NR:
			jmp = &op->op.nr.no_match;
			break;
		case OP_CMP:
			jmp = &op->op.cmp.jmp;
			break;
		default:
			continue;
		}

		if (jmp->offset == type) {
			jmp->offset = g->ip.offset;
			debug("    linked jump of instruction #%i to #%i",
			      op - (struct op *)g->g.inst, g->ip.offset);
		}
	}
}

void link_block(struct gluten_ctx *g)
{
	debug("   Linking block...");
	gluten_link(g, JUMP_NEXT_BLOCK, (struct op *)gluten_ptr(&g->g, g->lr));
}

void link_match(struct gluten_ctx *g)
{
	debug("   Linking match...");
	gluten_link(g, JUMP_NEXT_MATCH, (struct op *)gluten_ptr(&g->g, g->mr));
}

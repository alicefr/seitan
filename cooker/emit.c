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
	"INT",  "INTMASK",  "INTFLAGS",
	"U32",  "U32MASK",  "U32FLAGS",
	"LONG", "LONGMASK", "LONGFLAGS",
	"STRING",
	"STRUCT", "SELECT",
	"PID",
	"PORT", "IPV4", "IPV6",
	"FDPATH",
	NULL
};

static const char *cmp_type_str[] = { "EQ", "GT", "GE", "LT", "LE", NULL };

void emit_nr(struct gluten_ctx *g, long number)
{
	struct op_nr *nr = (struct op_nr *)gluten_ptr(&g->g, g->ip);

	nr->nr = number;
	nr->no_match.type = OFFSET_INSTRUCTION;
	nr->no_match.offset = NEXT_BLOCK;

	debug("   %i: OP_NR %li, < >", g->ip.offset, number);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

void emit_load(struct gluten_ctx *g, struct gluten_offset dst,
	       int index, size_t len)
{
	struct op_load *load = (struct op_load *)gluten_ptr(&g->g, g->ip);

	load->src.type = OFFSET_SECCOMP_DATA;
	load->src.offset = index;

	load->dst = dst;

	debug("   %i: OP_LOAD #%i < %i (%lu)", g->ip.offset, dst.offset,
					       index, len);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

void emit_cmp(struct gluten_ctx *g, enum op_cmp_type cmp,
	      struct gluten_offset x, struct gluten_offset y, size_t size,
	      enum jump_type jmp)
{
	struct op_cmp *op = (struct op_cmp *)gluten_ptr(&g->g, g->ip);

	op->x = x;
	op->y = y;
	op->size = size;
	op->cmp = cmp;
	op->jmp = jmp;

	debug("   %i: OP_CMP (#%lu) %%%lu %s %%%lu", g->ip.offset, size,
	      x.offset, cmp_type_str[cmp], y.offset);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

void emit_cmp_field(struct gluten_ctx *g, enum op_cmp_type cmp,
		    struct field *field,
		    struct gluten_offset base, struct gluten_offset match,
		    enum jump_type jmp)
{
	base.offset += field->offset;

	emit_cmp(g, cmp, base, match,
		 field->strlen ? field->strlen : gluten_size[field->type],
		 jmp);
}

struct gluten_offset emit_data(struct gluten_ctx *g, enum type type,
			       union value *value)
{
	void *p = gluten_ptr(&g->g, g->cp);
	struct gluten_offset ret = g->cp;

	if (type == INT) {
		*(int *)p = value->v_int;
		debug("   C#%i: (%s) %i", g->cp.offset, type_str[type],
		      value->v_int);
		if ((g->cp.offset += sizeof(int)) > RO_DATA_SIZE)
			die("   Read-only data section exceeded");
	}

	return ret;
}

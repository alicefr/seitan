// SPDX-License-Identifier: GPL-3.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/emit.c - Generate gluten (bytecode) instructions and read-only data
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *         Alice Frosi <afrosi@redhat.com>
 */

#include "cooker.h"
#include "gluten.h"
#include "util.h"
#include "emit.h"

static const char *type_str[] = {
	"UNDEF", "NONE",
	"INT", "U32", "U64", "LONG",
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

	debug("   %i: OP_NR: if syscall number is not C#%lu, jump to %s",
	      g->ip.offset, number.offset, jump_name[nr->no_match.offset]);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_call() - Emit OP_CALL instruction: execute a system call
 * @g:		gluten context
 * @ns:		NS_SPEC_NONE-terminated array of namespaces references
 * @nr:		System call number
 * @count:	Argument count
 * @is_ptr:	Array indicating whether arguments need to be dereferenced
 * @args:	Offsets of arguments
 * @ret_offset:	Offset where return value must be saved, can be OFFSET_NULL
 */
void emit_call(struct gluten_ctx *g, struct ns_spec *ns, long nr,
	       unsigned count, bool is_ptr[6],
	       struct gluten_offset offset[6], struct gluten_offset ret_offset)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct gluten_offset o1 = { 0 }, o2 = { 0 };
	struct op_call *call = &op->op.call;
	struct syscall_desc *desc;
	unsigned ns_count, i;
	struct ns_spec *ctx;

	op->type = OP_CALL;
	for (ns_count = 0; ns[ns_count].spec != NS_SPEC_NONE; ns_count++);

	if (ns_count) {
		o1 = gluten_ro_alloc(g, sizeof(struct ns_spec) * ns_count);
		ctx = (struct ns_spec *)gluten_ptr(&g->g, o1);
		memcpy(ctx, ns, sizeof(struct ns_spec) * ns_count);
	}

	o2 = gluten_ro_alloc(g, sizeof(struct syscall_desc) +
			       sizeof(struct gluten_offset) *
			       (count + (ret_offset.type != OFFSET_NULL)));
	desc = (struct syscall_desc *)gluten_ptr(&g->g, o2);
	desc->nr = nr;
	desc->arg_count = count;
	desc->has_ret = ret_offset.type != OFFSET_NULL;
	for (i = 0; i < count; i++)
		desc->arg_deref |= BIT(i) * is_ptr[i];
	desc->context = o1;
	memcpy(desc->args, offset, sizeof(struct gluten_offset) * count);
	desc->args[count] = ret_offset;

	debug("   %i: OP_CALL: %i, arguments:", g->ip.offset, nr);
	for (i = 0; i < count; i++) {
		debug("\t%i: %s %s%i", i, gluten_offset_name[offset[i].type],
		      is_ptr[i] ? "*" : "", offset[i].offset);
	}
	if (desc->has_ret)
		debug("\treturn: %s %i", gluten_offset_name[ret_offset.type],
		      offset[i].offset);
	call->desc = o2;

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
		 field->size ? field->size : gluten_size[field->type],
		 jmp);
}

/**
 * emit_return() - Emit OP_RETURN instruction: return value
 * @g:		gluten context
 * @v:		Pointer to return value
 */
void emit_return(struct gluten_ctx *g, struct gluten_offset v)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_return *ret = &op->op.ret;

	op->type = OP_RETURN;
	ret->val = v;

	debug("   %i: OP_RETURN:",  g->ip.offset);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_block() - Emit OP_BLOCK instruction: return error value
 * @g:		gluten context
 * @error:	Error value
 */
void emit_block(struct gluten_ctx *g, int32_t error)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_block *block = &op->op.block;

	op->type = OP_BLOCK;
	block->error = error;

	debug("   %i: OP_BLOCK: %d", g->ip.offset, error);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_copy(): Emit OP_COPY instruction: copy between given offsets
 * @g:		gluten context
 * @dst:	gluten pointer to destination
 * @src:	gluten pointer to source
 * @size:	Bytes to copy
 */
void emit_copy(struct gluten_ctx *g,
	       struct gluten_offset dst, struct gluten_offset src, size_t size)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_copy *copy = &op->op.copy;

	op->type = OP_COPY;

	copy->dst = dst;
	copy->src = src;
	copy->size = size;

	debug("   %i: OP_COPY: %lu bytes from %s: #%lu to %s: #%lu",
	      g->ip.offset, size,
	      gluten_offset_name[src.type], src.offset,
	      gluten_offset_name[dst.type], dst.offset);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_copy_field() - Emit OP_COPY for a given field type
 * @g:		gluten context
 * @field:	Description of field from system call model
 * @dst:	gluten pointer to destination
 * @src:	gluten pointer to source
 */
void emit_copy_field(struct gluten_ctx *g, struct field *field,
		     struct gluten_offset dst, struct gluten_offset src)
{
	emit_copy(g, dst, src,
		  field->size ? field->size : gluten_size[field->type]);
}

static struct gluten_offset emit_data_do(struct gluten_ctx *g,
					 struct gluten_offset offset,
					 enum type type, size_t str_len,
					 union value *value, bool add)
{
	void *p = gluten_ptr(&g->g, offset);
	struct gluten_offset ret = offset;

	if (!p) {
		if (type == STRING)
			ret = gluten_ro_alloc(g, str_len);
		else
			ret = gluten_ro_alloc_type(g, type);

		p = gluten_ptr(&g->g, ret);
	}

	switch (type) {
	case INT:
		if (add) {
			*(int *)p |= value->v_int;
			debug("   C#%i |= (%s) %i",
			      ret.offset, type_str[type], value->v_int);
		} else {
			*(int *)p = value->v_int;
			debug("   C#%i := (%s) %i",
			      ret.offset, type_str[type], value->v_int);
		}

		break;
	case LONG:
	case U64:
		if (add) {
			*(uint64_t *)p |= value->v_num;
			debug("   C#%i |= (%s) %llu",
			      ret.offset, type_str[type], value->v_num);
		} else {
			*(uint64_t *)p = value->v_num;
			debug("   C#%i := (%s) %llu",
			      ret.offset, type_str[type], value->v_num);
		}

		break;
	case STRING:
		strncpy(p, value->v_str, str_len);
		debug("   C#%i: (%s:%i) %s", g->cp.offset, type_str[type],
		      str_len, value->v_str);

		break;
	default:
		;
	}

	return ret;
}

struct gluten_offset emit_data(struct gluten_ctx *g, enum type type,
			       size_t str_len, union value *value)
{
	struct gluten_offset offset = { .type = OFFSET_NULL, .offset = 0 };

	return emit_data_do(g, offset, type, str_len, value, false);
}

struct gluten_offset emit_data_at(struct gluten_ctx *g,
				  struct gluten_offset offset,
				  enum type type, union value *value)
{
	return emit_data_do(g, offset, type,
			    (type == STRING) ? strlen(value->v_str) : 0, value,
			    false);
}

struct gluten_offset emit_data_or(struct gluten_ctx *g,
				  struct gluten_offset offset,
				  enum type type, union value *value)
{
	return emit_data_do(g, offset, type,
			    (type == STRING) ? strlen(value->v_str) : 0, value,
			    true);
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
	debug(" Linking block...");
	gluten_link(g, JUMP_NEXT_BLOCK, (struct op *)gluten_ptr(&g->g, g->lr));
}

void link_match(struct gluten_ctx *g)
{
	debug("   Linking match...");
	gluten_link(g, JUMP_NEXT_MATCH, (struct op *)gluten_ptr(&g->g, g->mr));
}

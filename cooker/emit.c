// SPDX-License-Identifier: GPL-2.0-or-later

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
#include "filter.h"
#include "util.h"
#include "emit.h"

static const char *type_str[] = {
	"UNDEF", "NONE",
	"USHORT", "INT", "U32", "U64", "LONG",
	"STRING",
	"STRUCT", "SELECT", "SELECTED",
	"PID",
	"PORT", "IPV4", "IPV6",
	"GNU_DEV_MAJOR", "GNU_DEV_MINOR",
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
 * emit_fd() - Emit OP_FD instruction: add/set file descriptor in target
 * @g:		gluten context
 * @desc:	Pointer to file descriptors specification
 */
void emit_fd(struct gluten_ctx *g, struct fd_desc *desc)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_fd *fd = &op->op.fd;
	struct gluten_offset o;
	struct fd_desc *dst;

	op->type = OP_FD;

	o = gluten_ro_alloc(g, sizeof(struct fd_desc));
	dst = (struct fd_desc *)gluten_ptr(&g->g, o);
	memcpy(dst, desc, sizeof(struct fd_desc));
	fd->desc = o;

	debug("   %i: OP_FD: ...", g->ip.offset);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_call() - Emit OP_CALL instruction: execute a system call
 * @g:		gluten context
 * @context:	CONTEXT_SPEC_NONE-terminated array of context references
 * @nr:		System call number
 * @count:	Argument count
 * @is_ptr:	Array indicating whether arguments need to be dereferenced
 * @args:	Offsets of arguments
 * @ret_offset:	Offset where return value must be saved, can be OFFSET_NULL
 */
void emit_call(struct gluten_ctx *g, struct context_desc *cdesc, long nr,
	       unsigned count, bool is_ptr[6],
	       struct gluten_offset offset[6], struct gluten_offset ret_offset)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct gluten_offset o1 = { 0 }, o2 = { 0 };
	struct op_call *call = &op->op.call;
	struct context_desc *c = cdesc;
	struct syscall_desc *desc;
	unsigned i;

	op->type = OP_CALL;

	for (i = 0; c[i].spec != CONTEXT_SPEC_NONE; i++);
	if (i) {
		o1 = gluten_ro_alloc(g, sizeof(struct context_desc) * i);
		c = (struct context_desc *)gluten_ptr(&g->g, o1);
		memcpy(c, cdesc, sizeof(struct context_desc) * i);
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
	load->size = len;

	debug("   %i: OP_LOAD: #%i < args[%i] (size: %lu)",
	      g->ip.offset, dst.offset, index, len);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

void emit_store(struct gluten_ctx *g, struct gluten_offset dst,
		struct gluten_offset src, struct gluten_offset count)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_store *store = &op->op.store;

	op->type = OP_STORE;

	store->dst = dst;
	store->src = src;
	store->count = count;

	debug("   %i: OP_STORE: #%i", g->ip.offset);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_resolved() - Emit OP_RESOLVEFD instruction: resolve file descriptor with path
 * @g:		gluten context
 * @fd:		offset of the file descriptor value
 * @path:	offset of the path
 * @path_size:	size of the path
 */
void emit_resolvefd(struct gluten_ctx *g, struct gluten_offset fd,
		     struct gluten_offset path, size_t path_size)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_resolvefd *resfd = &op->op.resfd;
	struct gluten_offset o;
	struct resolvefd_desc *desc;

	op->type = OP_RESOLVEDFD;
        o = gluten_ro_alloc(g, sizeof(struct resolvefd_desc));
        desc = (struct resolvefd_desc *)gluten_ptr(&g->g, o);

	desc->fd = fd;
	desc->path = path;
	desc->path_max = path_size;

	resfd->desc = o;

	debug("   %i: OP_RESOLVEDFD:", g->ip.offset);
	debug("   \tfd: %s offset=%d", gluten_offset_name[fd.type], fd.offset);
	debug("   \tpath: %s offset=%d size=%d", gluten_offset_name[path.type],
	      path.offset, path_size);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");
}

/**
 * emit_bitwise(): Emit OP_BITWISE instruction: bitwise operation and store
 * @g:		gluten context
 * @type:	Type of operands
 * @op_type:	Type of bitwise operation
 * @dst:	gluten pointer to destination operand, can be OFFSET_NULL
 * @x:		gluten pointer to first source operand
 * @y:		gluten pointer to second source operand
 *
 * Return: offset to destination operand, allocated here if not given
 */
struct gluten_offset emit_bitwise(struct gluten_ctx *g, enum type type,
				  enum bitwise_type op_type,
				  struct gluten_offset dst,
				  struct gluten_offset x,
				  struct gluten_offset y)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_bitwise *op_bitwise = &op->op.bitwise;
	struct gluten_offset o;
	struct bitwise_desc *desc;

	op->type = OP_BITWISE;

	o = gluten_ro_alloc(g, sizeof(struct bitwise_desc));
	desc = (struct bitwise_desc *)gluten_ptr(&g->g, o);

	desc->size = gluten_size[type];
	desc->type = op_type;
	if (dst.type == OFFSET_NULL)
		desc->dst = gluten_rw_alloc(g, desc->size);
	else
		desc->dst = dst;
	desc->x    = x;
	desc->y    = y;

	op_bitwise->desc = o;

	debug("   %i: OP_BITWISE: %s: #%lu (size: %lu) := %s: #%lu %s %s: #%lu",
	      g->ip.offset,
	      gluten_offset_name[desc->dst.type], desc->dst.offset, desc->size,
	      gluten_offset_name[desc->x.type],   desc->x.offset,
	      bitwise_type_str[op_type],
	      gluten_offset_name[desc->y.type],   desc->y.offset);

	if (++g->ip.offset > INST_MAX)
		die("Too many instructions");

	return desc->dst;
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
	struct gluten_offset o;
	struct cmp_desc *desc;

	op->type = OP_CMP;

	o = gluten_ro_alloc(g, sizeof(struct cmp_desc));
	desc = (struct cmp_desc *)gluten_ptr(&g->g, o);

	desc->x = x;
	desc->y = y;
	desc->size = size;
	desc->cmp = cmp_type;
	desc->jmp.type = OFFSET_INSTRUCTION;
	desc->jmp.offset = jmp;

	cmp->desc = o;

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
 * @v:		offset of the return value
 * @error:	error value
 * @cont 	if the filtered syscall needs to be executed
 */
void emit_return(struct gluten_ctx *g, struct gluten_offset v, int32_t error,
		 bool cont)
{
	struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);
	struct op_return *ret = &op->op.ret;
	struct gluten_offset o;
	struct return_desc *desc;

	op->type = OP_RETURN;

	o = gluten_ro_alloc(g, sizeof(struct return_desc));
	desc = (struct return_desc *)gluten_ptr(&g->g, o);

	desc->val = v;
	desc->error = error;
	desc->cont = cont;

	ret->desc = o;

	debug("   %i: OP_RETURN:",  g->ip.offset);
	debug("  \t val=(%s %d) errno=%d cont=%s", gluten_offset_name[v.type],
	      v.offset, error, cont ? "true" : "false");

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

/**
 * emit_end() - Emit OP_END instruction: end of the operation block
 * @g:         gluten context
 */
void emit_end(struct gluten_ctx *g)
{
       struct op *op = (struct op *)gluten_ptr(&g->g, g->ip);

       op->type = OP_END;

       debug("   %i: OP_END",  g->ip.offset);

       if (++g->ip.offset > INST_MAX)
               die("Too many instructions");
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
	case USHORT:
	case INT:
	case U32:
		if (add) {
			*(int *)p |= value->v_int;
			debug("   C#%i |= (%s) %i (0x%04x)",
			      ret.offset, type_str[type],
			      value->v_num, value->v_num);
		} else {
			*(int *)p = value->v_int;
			debug("   C#%i := (%s) %i (0x%04x)",
			      ret.offset, type_str[type],
			      value->v_num, value->v_num);
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
	case GNU_DEV_MAJOR:
		*(unsigned long long int *)p |= makedev(value->v_num, 0);
		debug("   C#%i |= (%s) %llu",
		      ret.offset, type_str[type], value->v_num);

		break;
	case GNU_DEV_MINOR:
		*(unsigned long long int *)p |= makedev(0, value->v_num);
		debug("   C#%i |= (%s) %llu",
		      ret.offset, type_str[type], value->v_num);

		break;
	case STRING:
		strncpy(p, value->v_str, str_len);
		debug("   C#%i: (%s:%i) %s", ret.offset, type_str[type],
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
	return emit_data_do(g, NULL_OFFSET, type, str_len, value, false);
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

struct gluten_offset emit_seccomp_data(int index) {
	struct gluten_offset o = { OFFSET_SECCOMP_DATA, index };
	return o;
}

static void gluten_link(struct gluten_ctx *g, enum jump_type type,
			struct op *start)
{
	struct gluten_offset *jmp;
	struct cmp_desc *desc;
	struct op *op;

	for (op = (struct op *)start; op->type; op++) {
		switch (op->type) {
		case OP_NR:
			jmp = &op->op.nr.no_match;
			break;
		case OP_CMP:
			desc = (struct cmp_desc *)gluten_ptr(&g->g,
							     op->op.cmp.desc);
			jmp = &desc->jmp;
			break;
		default:
			continue;
		}

		if (jmp->offset == type) {
			jmp->offset = g->ip.offset;

			if (jmp->offset >= INST_MAX)
				die("jump after end of instruction area");

			debug("    linked jump of instruction #%i to #%i",
			      op - (struct op *)g->g.inst, g->ip.offset);
		}
	}
}

void emit_bpf_arg(int index, enum type type, union value v, union value mask,
		  enum op_cmp_type cmp)
{
	struct bpf_field bpf;

	/* gluten uses the comparison to skip to the next match, the BPF filter
	 * uses it to notify instead.
	 */
	if (mask.v_num)
		bpf.cmp = (cmp == CMP_EQ) ? AND_NE : AND_EQ;
	else
		bpf.cmp = (cmp == CMP_EQ) ? NE : EQ;

	bpf.arg = index;

	if (TYPE_IS_64BIT(type)) {
		bpf.value.v64 = v.v_num;
		bpf.op2.v64 = mask.v_num;
		bpf.type = BPF_U64;
	} else {
		bpf.value.v32 = v.v_num;
		bpf.op2.v32 = mask.v_num;
		bpf.type = BPF_U32;
	}

	filter_add_check(&bpf);
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

void link_matches(struct gluten_ctx *g)
{
	debug("   Linking matches...");
	gluten_link(g, JUMP_NEXT_ACTION, (struct op *)gluten_ptr(&g->g, g->lr));
}

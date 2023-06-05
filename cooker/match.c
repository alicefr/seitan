// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/match.c - Parse "match" rules from JSON recipe into bytecode
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "parson.h"
#include "calls.h"
#include "cooker.h"
#include "gluten.h"
#include "emit.h"
#include "filter.h"
#include "parse.h"
#include "util.h"

#include "calls/net.h"

/**
 * arg_load() - Allocate and build bytecode for one syscall argument
 * @g:		gluten context
 * @a:		Argument description from model
 *
 * Return: offset where (full) argument is stored
 */
static struct gluten_offset arg_load(struct gluten_ctx *g, struct arg *a)
{
	struct gluten_offset offset;
	int index = a->pos;
	size_t size;

	if (a->f.type == SELECTED) {
		if (g->selected_arg[index]->f.type != UNDEF)
			size = g->selected_arg[index]->f.size;
		else
			die("   no storage size for argument %s", a->f.name);
	} else {
		size = a->f.size;
	}

	if (!size) {
		g->match_dst[index].offset.type = OFFSET_SECCOMP_DATA;
		g->match_dst[index].offset.offset = index;
		g->match_dst[index].len = 0;
		return g->match_dst[index].offset;
	}

	filter_needs_deref();

	if (g->match_dst[index].len)	/* Already allocated */
		return g->match_dst[index].offset;

	offset = gluten_rw_alloc(g, size);

	g->match_dst[index].offset = offset;
	g->match_dst[index].len = size;

	emit_load(g, offset, index, size);

	return offset;
}

/**
 * parse_field() - Parse generic field along with JSON value
 * @g:		gluten context
 * @offset:	Base offset of container field (actual offset for non-compound)
 * @index:	Index of parent syscall argument
 * @f:		Field from syscall model
 * @jvalue:	JSON value
 *
 * Return: parsed value for simple types, empty value otherwise
 */
static union value parse_field(struct gluten_ctx *g,
			       struct gluten_offset offset,
			       int index, struct field *f, JSON_Value *jvalue)
{
	struct gluten_offset const_offset;
	union value v = { .v_num = 0 };
	struct field *f_inner;
	const char *tag_name;
	JSON_Object *tmp;
	JSON_Value *sel;

	if (f->name)
		debug("    parsing field name %s", f->name);

	if (json_value_get_type(jvalue) == JSONObject &&
	    (tmp = json_value_get_object(jvalue)) &&
	    (tag_name = json_object_get_string(tmp, "tag"))) {
		debug("    setting tag reference '%s'", tag_name);
		gluten_add_tag(g, tag_name, offset);

		jvalue = json_object_get_value(tmp, "value");
	}

	/* Nothing to match on: just store as reference */
	if (!jvalue)
		return v;

	offset.offset += f->offset;

	switch (f->type) {
	case USHORT:
	case INT:
	case LONG:
	case U32:
		if (f->flags == FLAGS) {
			/* fetch/combine expr algebra loop */
			;
		}
		if (f->flags == MASK) {
			/* calculate mask first */
			;
		}

		v.v_num = value_get_num(f->desc.d_num, jvalue);
		const_offset = emit_data(g, f->type, 0, &v);
		emit_cmp(g, CMP_NE, offset, const_offset, gluten_size[f->type],
			 JUMP_NEXT_BLOCK);
		break;
	case SELECT:
		f_inner = f->desc.d_select->field;

		if ((tmp = json_value_get_object(jvalue))) {
			if (!(sel = json_object_get_value(tmp, f_inner->name)))
				die("   no selector for '%s'", f_inner->name);
		} else {
			sel = jvalue;
		}

		v = parse_field(g, offset, index, f_inner, sel);

		f = select_field(g, index, f->desc.d_select, v);
		if (f)
			parse_field(g, offset, index, f, jvalue);
		break;
	case STRING:
		v.v_str = json_value_get_string(jvalue);
		if (strlen(v.v_str) + 1 > f->size)
			die("   string %s too long for field", v.v_str);

		const_offset = emit_data(g, STRING, strlen(v.v_str) + 1, &v);
		emit_cmp(g, CMP_NE, offset, const_offset, strlen(v.v_str) + 1,
			 JUMP_NEXT_BLOCK);
		break;
	case STRUCT:
		for (f_inner = f->desc.d_struct; f_inner->name; f_inner++) {
			JSON_Value *field_value;

			tmp = json_value_get_object(jvalue);
			field_value = json_object_get_value(tmp, f_inner->name);
			if (!field_value)
				continue;

			parse_field(g, offset, index, f_inner, field_value);
		}
		break;
	default:
		;
	}

	return v;
}

/**
 * parse_arg() - Parse syscall argument from JSON, following model
 * @g:		gluten context
 * @a:		Argument description from model
 * @value:	JSON value for argument
 */
static void parse_arg(struct gluten_ctx *g, JSON_Value *jvalue, struct arg *a)
{
	struct gluten_offset offset;

	debug("   Parsing match argument %s", a->f.name);

	offset = arg_load(g, a);

	parse_field(g, offset, a->pos, &a->f, jvalue);
}

/**
 * parse_match() - Parse one "match" item in syscall rules
 * @g:		gluten context
 * @obj:	Matching rule for one syscall
 * @args:	Description of arguments from syscall model
 */
static void parse_match(struct gluten_ctx *g, JSON_Object *obj,
			struct arg *args)
{
	unsigned count = 0;
	struct arg *a;

	for (a = args; a->f.name; a++) {
		struct arg *real_arg = a;
		JSON_Value *jvalue;

		if (a->f.type == SELECTED) {
			if (!(real_arg = g->selected_arg[a->pos]))
				die("  No argument selected for %s", a->f.name);
		}

		if ((jvalue = json_object_get_value(obj, real_arg->f.name))) {
			count++;
			parse_arg(g, jvalue, real_arg);
		}
	}

	if (count != json_object_get_count(obj))
		die("  Stray elements in match");
}

/**
 * handle_matches() - Parse "match" array, find syscall models
 * @g:		gluten context
 * @value:	"match" object containing array of rules
 */
void handle_matches(struct gluten_ctx *g, JSON_Value *value)
{
	JSON_Array *matches = json_value_get_array(value);
	unsigned i;

	for (i = 0; i < json_array_get_count(matches); i++) {
		JSON_Object *match, *args;
		struct call **set, *call;
		const char *name;

		g->mr = g->ip;

		match = json_array_get_object(matches, i);
		name = json_object_get_name(match, 0);
		args = json_object_get_object(match, name);
		debug(" Parsing match %i: %s", i, name);

		for (set = call_sets, call = set[0]; *set; ) {
			if (!call->name) {
				set++;
				call = set[0];
				continue;
			}

			if (!strcmp(name, call->name)) {
				union value v = { .v_num = call->number };

				debug("  Found description for %s", name);
				emit_nr(g, emit_data(g, U64, 0, &v));

				filter_notify(call->number);

				parse_match(g, args, call->args);
				break;
			}
			call++;
		}

		if (!*set)
			die("  Unknown system call: %s", name);

		link_match(g);
	}
}

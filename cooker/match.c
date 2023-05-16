// SPDX-License-Identifier: GPL-3.0-or-later

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
#include "util.h"

#include "calls/net.h"

/**
 * struct rule_parser - Parsing handler for JSON rule type
 * @type:	JSON key name
 * @fn:		Parsing function
 */
struct rule_parser {
	const char *type;
	int (*fn)(struct gluten_ctx *g, JSON_Value *value);
};

/**
 * arg_load() - Allocate and build bytecode for one syscall argument
 * @g:		gluten context
 * @a:		Argument description from model
 *
 * Return: offset where (full) argument is stored
 */
static struct gluten_offset arg_load(struct gluten_ctx *g, struct arg *a)
{
	int index = a->pos;
	size_t size;

	if (a->type == SELECTED) {
		if (g->selected_arg[index]->type != UNDEF)
			size = g->selected_arg[index]->size;
		else
			die("   no storage size for argument %s", a->name);
	} else {
		size = a->size;
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

	g->match_dst[index].offset = gluten_alloc(g, size);
	g->match_dst[index].len = size;

	emit_load(g, g->match_dst[index].offset, index, size);

	return g->match_dst[index].offset;
}

/**
 * value_get_num() - Get numeric value from description matching JSON input
 * @desc:	Description of possible values from model
 * @value:	JSON value
 *
 * Return: numeric value
 */
static long long value_get_num(struct num *desc, JSON_Value *value)
{
	const char *s = NULL;
	long long n;

	if (desc) {
		s = json_value_get_string(value);
		for (; desc->name && s && strcmp(s, desc->name); desc++);
		if (s && !desc->name)
			die("   Invalid value %s", s);

		n = desc->value;
	}

	if (!s) {
		if (json_value_get_type(value) != JSONNumber)
			die("   Invalid value type");

		n = json_value_get_number(value);
	}

	return n;
}

/**
 * value_get() - Get generic value from description matching JSON input
 * @desc:	Description of possible values from model
 * @type:	Data type from model
 * @value:	JSON value
 * @out:	Corresponding bytecode value, set on return
 */
static void value_get(union desc desc, enum type type, JSON_Value *value,
		      union value *out)
{
	if (TYPE_IS_NUM(type))
		out->v_num = value_get_num(desc.d_num, value);
}

/**
 * select_desc() - Get description and type for selected value
 * @g:		gluten context
 * @s:		Possible selection choices
 * @v:		Selector value
 * @pos:	Index of syscall argument being parsed
 * @type:	Type of selected value, set on return
 * @desc:	Description of selected value, set on return
 */
static void select_desc(struct gluten_ctx *g, struct select *s, union value v,
			int pos, enum type *type, union desc *desc)
{
	if (TYPE_IS_NUM(s->field->type)) {
		struct select_num *d_num;

		for (d_num = s->desc.d_num; d_num->target.type; d_num++) {
			if (d_num->value == v.v_num) {
				if (d_num->target.pos == pos) {
					*type = d_num->target.type;
					*desc = d_num->target.desc;
				} else {
					pos = d_num->target.pos;
					g->selected_arg[pos] = &d_num->target;
					*type = NONE;
				}

				return;
			}
		}

		if (!d_num->target.type)
			die("   No match for numeric selector %i", v.v_num);
	}

	die("   not supported yet");
}

/**
 * parse_value() - Parse JSON value for generic item of data description
 * @g:		gluten context
 * @index:	Index of parent syscall argument
 * @offset:	Base offset of container field (actual offset for non-compound)
 * @type:	Data type, from model
 * @str_len:	Length of string, valid for STRING type only
 * @desc:	Description of possible values, from model
 * @value:	JSON value
 */
static void parse_value(struct gluten_ctx *g, int index,
			struct gluten_offset offset, enum type type,
			size_t str_len, union desc desc, JSON_Value *value)
{
	struct gluten_offset data_offset, const_offset;
	const char *tag_name;
	JSON_Object *tmp;
	struct field *f;
	union value v;

	if (type == SELECT) {
		struct select *select = desc.d_select;
		struct field *field = select->field;
		JSON_Value *sel;

		if ((tmp = json_value_get_object(value))) {
			if (!(sel = json_object_get_value(tmp, field->name)))
				die("   no selector for '%s'", field->name);
		} else {
			sel = value;
		}

		value_get(field->desc, field->type, sel, &v);
		const_offset = emit_data(g, field->type, field->strlen, &v);

		data_offset = offset;
		data_offset.offset += field->offset;

		emit_cmp_field(g, CMP_NE, field, data_offset, const_offset,
			       JUMP_NEXT_BLOCK);

		select_desc(g, select, v, index, &type, &desc);

		if (type == NONE)
			return;
	}

	if (json_value_get_type(value) == JSONObject &&
	    (tmp = json_value_get_object(value)) &&
	    (tag_name = json_object_get_string(tmp, "tag"))) {
		if (TYPE_IS_COMPOUND(type))
			die("Tag reference '%s' to compound value", tag_name);

		debug("   setting tag reference '%s'", tag_name);
		gluten_add_tag(g, tag_name, offset);

		value = json_object_get_value(tmp, "value");
	}

	/* Nothing to match on: just store as reference */
	if (!value)
		return;

	switch (type) {
	case INTFLAGS:
	case LONGFLAGS:
	case U32FLAGS:
		/* fetch/combine expr algebra loop */
	case INTMASK:
		/* calculate mask first */
		break;
	case INT:
	case LONG:
	case U32:
		v.v_num = value_get_num(desc.d_num, value);
		const_offset = emit_data(g, type, 0, &v);
		emit_cmp(g, CMP_NE, offset, const_offset, gluten_size[type],
			 JUMP_NEXT_BLOCK);
		break;
	case SELECT:
		/* TODO: check how nested selects should work */
		parse_value(g, index, offset, type, 0, desc, value);
		break;
	case STRING:
		v.v_str = json_value_get_string(value);
		if (strlen(v.v_str) + 1 > str_len)
			die("   string %s too long for field", v.v_str);

		const_offset = emit_data(g, STRING, strlen(v.v_str) + 1, &v);
		emit_cmp(g, CMP_NE, offset, const_offset, strlen(v.v_str) + 1,
			 JUMP_NEXT_BLOCK);
		break;
	case STRUCT:
		for (f = desc.d_struct; f->name; f++) {
			JSON_Value *field_value;

			tmp = json_value_get_object(value);
			field_value = json_object_get_value(tmp, f->name);
			if (!field_value)
				continue;

			parse_value(g, index, offset, f->type, f->strlen,
				    f->desc, field_value);
		}
	default:
		;
	}
}

/**
 * parse_arg() - Parse syscall argument from JSON, following model
 * @g:		gluten context
 * @name:	Name of argument (key) in JSON and model
 * @value:	JSON value for argument
 * @a:		Argument description from model
 */
static void parse_arg(struct gluten_ctx *g, const char *name, JSON_Value *value,
		      struct arg *a)
{
	struct gluten_offset offset;

	debug("  Parsing match argument %s", name);

	offset = arg_load(g, a);

	parse_value(g, a->pos, offset, a->type, a->size, a->desc, value);
}

/**
 * parse_match() - Parse one syscall rule in "match" array
 * @g:		gluten context
 * @obj:	Matching rule for one syscall
 * @args:	Description of arguments from syscall model
 */
static void parse_match(struct gluten_ctx *g, JSON_Object *obj,
			struct arg *args)
{
	unsigned count = 0;
	struct arg *a;

	for (a = args; a->name; a++) {
		struct arg *real_arg = a;
		JSON_Value *value;

		if (a->type == SELECTED) {
			if (!(real_arg = g->selected_arg[a->pos]))
				die("  No selection for argument %s", a->name);
		}

		if ((value = json_object_get_value(obj, real_arg->name))) {
			count++;
			parse_arg(g, real_arg->name, value, real_arg);
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

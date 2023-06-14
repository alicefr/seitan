// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/parse.c - JSON recipe parsing
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *         Alice Frosi <afrosi@redhat.com>
 */

#include "parson.h"
#include "calls.h"
#include "cooker.h"
#include "gluten.h"
#include "call.h"
#include "match.h"
#include "emit.h"
#include "util.h"

static void handle_fd(struct gluten_ctx *g, JSON_Value *value)
{
	JSON_Object *obj = json_value_get_object(value), *tmp;
	struct fd_desc desc = { .cloexec = 1 };
	JSON_Value *jvalue;
	const char *tag;

	debug(" Parsing \"fd\"");

	jvalue = json_object_get_value(obj, "src");
	if (json_value_get_type(jvalue) == JSONObject) {
		tmp = json_object_get_object(obj, "src");
		if (!tmp || !(tag = json_object_get_string(tmp, "tag")))
			die("invalid tag specification");
		desc.srcfd = gluten_get_tag(g, tag);
	} else if (json_value_get_type(jvalue) == JSONNumber) {
		union value v = { .v_num = json_value_get_number(jvalue) };
		desc.srcfd = emit_data(g, U32, 0, &v);
	} else {
		die("no valid \"src\" in \"fd\"");
	}

	jvalue = json_object_get_value(obj, "new");
	if (!jvalue) {
		;
	} else if (json_value_get_type(jvalue) == JSONObject) {
		tmp = json_object_get_object(obj, "new");
		if (!tmp || !(tag = json_object_get_string(tmp, "tag")))
			die("invalid tag specification");
		desc.newfd = gluten_get_tag(g, tag);
		desc.setfd = 1;
	} else if (json_value_get_type(jvalue) == JSONNumber) {
		union value v = { .v_num = json_value_get_number(jvalue) };
		desc.newfd = emit_data(g, U32, 0, &v);
		desc.setfd = 1;
	} else {
		die("invalid \"new\" in \"fd\"");
	}

	if (json_object_get_value(obj, "return"))
		desc.do_return = json_object_get_boolean(obj, "return");

	if (json_object_get_value(obj, "close_on_exec"))
		desc.cloexec = json_object_get_boolean(obj, "close_on_exec");

	emit_fd(g, &desc);
}

static void handle_limit(struct gluten_ctx *g, JSON_Value *value)
{
	(void)g;
	(void)value;
}

static void handle_write(struct gluten_ctx *g, JSON_Value *value)
{
	JSON_Object *obj = json_value_get_object(value);
	struct gluten_offset src, dst, count;
	const char *tag;

	if (!(tag = json_object_get_string(obj, "src")))
		die("invalid tag specification");
	src = gluten_get_tag(g, tag);

	if (!(tag = json_object_get_string(obj, "dst")))
		die("invalid tag specification");
	dst = gluten_get_tag(g, tag);

	if (!(tag = json_object_get_string(obj, "count")))
		die("invalid tag specification");
	count = gluten_get_tag(g, tag);

	emit_store(g, dst, src, count);
}

static void handle_return(struct gluten_ctx *g, JSON_Value *value)
{
	JSON_Object *obj = json_value_get_object(value);
	struct gluten_offset data = NULL_OFFSET;
	const char *tag;
	JSON_Value *jvalue;
	union value v = { .v_u64 = 0 };
	int32_t error = 0;
	bool cont = false;

	debug("  Parsing \"return\"");

	jvalue = json_object_get_value(obj, "error");
        if (json_value_get_type(jvalue) == JSONNumber)
		data = emit_data(g, U64, sizeof(v.v_u64), &v);
	else if ((tag = json_object_get_string(obj, "error")))
		data = gluten_get_tag(g, tag);

	jvalue = json_object_get_value(obj, "value");
        if (json_value_get_type(jvalue) == JSONNumber)
		data = emit_data(g, U64, sizeof(v.v_u64), &v);
	else if ((tag = json_object_get_string(obj, "value")))
		data = gluten_get_tag(g, tag);

	jvalue = json_object_get_value(obj, "continue");
        if (json_value_get_type(jvalue) == JSONBoolean) {
		cont = json_value_get_boolean(jvalue);
	}
	if (cont && (v.v_u64 != 0 || error != 0))
		die("  if continue is true, error and value needs to be zero");

	debug("  emit return: val=%ld errno=%d cont=%s", v.v_u64, error,
	      cont ? "true" : "false");

	emit_return(g, data, error, cont);
}

static void handle_context(struct gluten_ctx *g, JSON_Value *value)
{
	(void)g;
	(void)value;
}

/**
 * struct rule_parser - Parsing handler for JSON rule type
 * @type:	JSON key name
 * @fn:		Parsing function
 */
struct rule_parser {
	const char *type;
	void (*fn)(struct gluten_ctx *g, JSON_Value *value);
} parsers[] = {
	{ "match",	handle_matches },
	{ "call",	handle_calls },
	{ "write",	handle_write },
	{ "fd",		handle_fd },
	{ "limit",	handle_limit },
	{ "return",	handle_return },
	{ "context",	handle_context },
	{ NULL, NULL },
};

static union value value_get_set(struct num *desc, JSON_Array *set)
{
	struct num *tmp;
	union value n;
	unsigned i;

	for (i = 0; i < json_array_get_count(set); i++) {
		for (tmp = desc; tmp->name; tmp++) {
			if (!strcmp(tmp->name, json_array_get_string(set, i))) {
				n.v_num |= desc->value;
				break;
			}
		}

		if (!tmp->name)
			die("invalid flag'%s'", json_array_get_string(set, i));
	}

	return n;
}

void value_get_flags(struct num *desc, JSON_Object *obj,
		     union value *bitset, enum op_cmp_type *cmp,
		     union value *cmpterm)
{
	JSON_Array *set;

	if ((set = json_object_get_array(obj, "some"))) {
		*bitset = value_get_set(desc, set);
		*cmp = CMP_EQ;
		cmpterm->v_num = 0;
	} else if ((set = json_object_get_array(obj, "all"))) {
		*bitset = value_get_set(desc, set);
		*cmp = CMP_NE;
		*cmpterm = *bitset;
	} else if ((set = json_object_get_array(obj, "not"))) {
		*bitset = value_get_set(desc, set);
		*cmp = CMP_NE;
		cmpterm->v_num = 0;
	} else {
		die("unsupported flag quantifier");
	}
}

/**
 * value_get_mask() - Get union of all possible numeric values from description
 * @desc:	Description of possible values from model
 *
 * Return: numeric value
 */
long long value_get_mask(struct num *desc)
{
	long long n = 0;

	while ((desc++)->name)
		n |= desc->value;

	return n;
}

/**
 * value_get_num() - Get numeric value from description matching JSON input
 * @desc:	Description of possible values from model
 * @value:	JSON value
 *
 * Return: numeric value
 */
long long value_get_num(struct num *desc, JSON_Value *value)
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

ssize_t value_get_size(struct gluten_ctx *g, intptr_t id)
{
	if (!g)
		return -1;

	return gluten_get_attr(g, ATTR_SIZE, id).v_num;
}

/**
 * value_get() - Get generic value from description matching JSON input
 * @desc:	Description of possible values from model
 * @type:	Data type from model
 * @value:	JSON value
 * @out:	Corresponding bytecode value, set on return
 */
void value_get(union desc desc, enum type type, JSON_Value *value,
	       union value *out)
{
	if (TYPE_IS_NUM(type))
		out->v_num = value_get_num(desc.d_num, value);
}

/**
 * select_field() - Select field based on value and description
 * @g:		gluten context
 * @pos:	Index of syscall argument being parsed
 * @s:		Possible selection choices
 * @v:		Selector value
 *
 * Return: pointer to field, NULL if selector refers to a different argument
 */
struct field *select_field(struct gluten_ctx *g, int pos,
			   struct select *s, union value v)
{
	if (TYPE_IS_NUM(s->field->type)) {
		struct select_num *d_num;

		for (d_num = s->desc.d_num; d_num->target.f.type; d_num++) {
			if (d_num->value == v.v_num) {
				if (g && d_num->sel_size != -1) {
					v.v_num = d_num->sel_size;
					gluten_add_attr(g, ATTR_SIZE,
							(intptr_t)s, v);
				}

				if (d_num->target.pos == pos)
					return &d_num->target.f;

				if (g) {
					pos = d_num->target.pos;
					g->selected_arg[pos] = &d_num->target;
				}

				return NULL;
			}
		}

		if (!d_num->target.f.type)
			die("   No match for numeric selector %i", v.v_num);
	}

	die("   not supported yet");
}

/**
 * parse_block() - Parse a transformation block with rules
 * @g:		gluten context
 * @block:	Array of rules in block
 */
static void parse_block(struct gluten_ctx *g, JSON_Object *block)
{
	unsigned i;

	memset(g->selected_arg, 0, sizeof(g->selected_arg));
	memset(g->tags, 0, sizeof(g->tags));
	g->lr = g->ip;

	for (i = 0; i < json_object_get_count(block); i++) {
		struct rule_parser *parser;
		JSON_Value *rule;
		const char *type;

		type = json_object_get_name(block, i);
		rule = json_object_get_value(block, type);

		for (parser = parsers; parser->type; parser++) {
			if (!strcmp(type, parser->type)) {
				parser->fn(g, rule);
				break;
			}
		}

		if (!parser->type)
			die(" Invalid rule type: \"%s\"", type);
	}
	emit_end(g);
	link_block(g);
}

/**
 * parse_file() - Entry point for parsing of a JSON input file
 * @g:		gluten context
 * @path:	Input file path
 */
void parse_file(struct gluten_ctx *g, const char *path)
{
	JSON_Array *blocks;
	JSON_Value *root;
	JSON_Object *obj;
	unsigned i;

	root = json_parse_file_with_comments(path);
	if (json_value_get_type(root) != JSONArray)
		die("Invalid input file %s", path);

	blocks = json_value_get_array(root);
	for (i = 0; i < json_array_get_count(blocks); i++) {
		obj = json_array_get_object(blocks, i);

		debug("Parsing block %i", i);
		parse_block(g, obj);
	}
}

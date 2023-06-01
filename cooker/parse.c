// SPDX-License-Identifier: GPL-3.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/parse.c - JSON recipe parsing
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "parson.h"
#include "calls.h"
#include "cooker.h"
#include "gluten.h"
#include "call.h"
#include "match.h"
#include "emit.h"
#include "util.h"

static void handle_inject(struct gluten_ctx *g, JSON_Value *value)
{
	(void)g;
	(void)value;
}

static void handle_limit(struct gluten_ctx *g, JSON_Value *value)
{
	(void)g;
	(void)value;
}

static void handle_return(struct gluten_ctx *g, JSON_Value *value)
{
	union value v = { .v_u64 = json_value_get_number(value) };

	emit_return(g, emit_data(g, U64, sizeof(v.v_u64), &v));
}

static void handle_block(struct gluten_ctx *g, JSON_Value *value)
{
	emit_block(g, json_value_get_number(value));
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
	{ "inject",	handle_inject },
	{ "limit",	handle_limit },
	{ "return",	handle_return },
	{ "block",	handle_block },
	{ "context",	handle_context },
	{ NULL, NULL },
};

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

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
#include "emit.h"
#include "util.h"

#include "calls/net.h"

struct rule_parser {
	const char *type;
	int (*fn)(struct gluten_ctx *g, JSON_Value *value);
};

static int parse_match_load(struct gluten_ctx *g, struct arg *a)
{
	if (!a->size || g->match_dst[a->pos].len)
		return 0;

	g->match_dst[a->pos].offset = gluten_alloc(g, a->size);
	g->match_dst[a->pos].len = a->size;

	emit_load(g, g->match_dst[a->pos].offset, a->pos, a->size);

	return 0;
}

static long long parse_match_expr_num(struct arg_num *desc, JSON_Value *value)
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

static int parse_match_key(struct gluten_ctx *g, int index, enum arg_type type,
			   union arg_value desc, JSON_Value *value)
{
	JSON_Object *tmp;
	const char *ref;

	(void)index;

	if (json_value_get_type(value) == JSONObject &&
	    (tmp = json_value_get_object(value)) &&
	    (ref = json_object_get_string(tmp, "ref"))) {
		debug("   setting reference '%s'", ref);
		gluten_alloc_type(g, type);
		value = json_object_get_value(tmp, "value");
	}

	if (!value)
		return 0;

	switch (type) {
	case ARG_INTFLAGS:
	case ARG_LONGFLAGS:
	case ARG_U32FLAGS:
		/* fetch/combine expr algebra loop */
	case ARG_INTMASK:
		/* calculate mask first */
	case ARG_INT:
	case ARG_LONG:
	case ARG_U32:
		parse_match_expr_num(desc.d_num, value);
		//emit_cmp(...);
	default:
		;
	}

	return 0;
}

static int parse_match_arg(struct gluten_ctx *g, const char *name,
			   JSON_Value *value, struct arg *a)
{
	debug("  Parsing match argument %s", name);

	parse_match_load(g, a);
	parse_match_key(g, a->pos, a->type, a->desc, value);

	return 0;
}

static int parse_match(struct gluten_ctx *g, JSON_Object *obj, struct arg *args)
{
	unsigned count = 0;
	struct arg *a;

	for (a = args; a->name; a++) {
		JSON_Value *value;

		if ((value = json_object_get_value(obj, a->name))) {
			count++;
			parse_match_arg(g, a->name, value, a);
		}
	}

	if (count != json_object_get_count(obj))
		die("  Stray elements in match");

	return 0;
}

static int parse_matches(struct gluten_ctx *g, JSON_Value *value)
{
	JSON_Array *matches = json_value_get_array(value);
	unsigned i;

	for (i = 0; i < json_array_get_count(matches); i++) {
		JSON_Object *match, *args;
		struct call **set, *call;
		const char *name;

		g->lr = g->ip;
		g->sp = 0;

		match = json_array_get_object(matches, i);
		name = json_object_get_name(match, 0);
		args = json_object_get_object(match, name);
		debug(" Parsing match %i: %s", i, name);

		for (set = call_sets, call = set[0]; *set; call++) {
			if (!call->name) {
				set++;
				continue;
			}

			if (!strcmp(name, call->name)) {
				debug("  Found handler for %s", name);
				emit_nr(g, call->number);

				parse_match(g, args, call->args);
				break;
			}
		}

		if (!*set)
			die("  Unknown system call: %s", name);
	}

	return 0;
}

static int parse_call(struct gluten_ctx *g, JSON_Value *value)
{
	(void)g;
	(void)value;
	return 0;
}

static int parse_inject(struct gluten_ctx *g, JSON_Value *value)
{
	(void)g;
	(void)value;
	return 0;
}

struct rule_parser parsers[] = {
	{ "match", parse_matches },
	{ "call", parse_call },
	{ "inject", parse_inject },
	{ NULL, NULL },
};

static int parse_block(struct gluten_ctx *g, JSON_Object *block)
{
	unsigned i;

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

	return 0;
}

int parse_file(struct gluten_ctx *g, const char *path)
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

	return 0;
}

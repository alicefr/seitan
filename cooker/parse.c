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
#include "match.h"
#include "emit.h"
#include "util.h"

#include "calls/net.h"

static void handle_call(struct gluten_ctx *g, JSON_Value *value)
{
	(void)g;
	(void)value;
}

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
	(void)g;
	(void)value;
}

static void handle_block(struct gluten_ctx *g, JSON_Value *value)
{
	(void)g;
	(void)value;
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
	{ "call",	handle_call },
	{ "inject",	handle_inject },
	{ "limit",	handle_limit },
	{ "return",	handle_return },
	{ "block",	handle_block },
	{ "context",	handle_context },
	{ NULL, NULL },
};

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

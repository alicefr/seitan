/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef GLUTEN_H
#define GLUTEN_H

#define COOKER
#include <gluten.h>

struct gluten_arg_data {
	struct gluten_offset offset;
	size_t len;
};

struct gluten_tag_data {
	const char *name;
	struct gluten_offset offset;
	size_t len;
};

struct gluten_ctx {
	struct gluten_offset ip;
	struct gluten_offset lr;
	struct gluten_offset mr;
	struct gluten_offset cp;
	struct gluten_offset dp;

	struct gluten g;

	struct gluten_arg_data match_dst[CALL_ARGS];
	struct gluten_arg_data call_src[CALL_ARGS];

	struct gluten_tag_data tags[TAGS_MAX];

	struct arg *selected_arg[6];
};

/**
 * enum jump_type - Indicate direction of jump before linking phase
 */
enum jump_type {
	JUMP_NEXT_BLOCK,
	JUMP_NEXT_MATCH,
	JUMP_END,
	JUMP_COUNT,
};

struct gluten_offset gluten_alloc(struct gluten_ctx *g, size_t size);
struct gluten_offset gluten_alloc_type(struct gluten_ctx *g, enum type type);
void gluten_add_tag(struct gluten_ctx *g, const char *name,
		    struct gluten_offset offset);
void gluten_init(struct gluten_ctx *g);
void gluten_block_init(struct gluten_ctx *g);
void gluten_write(struct gluten_ctx *g, const char *path);

extern size_t gluten_size[TYPE_COUNT];
extern const char *jump_name[JUMP_COUNT];

#endif /* GLUTEN_H */

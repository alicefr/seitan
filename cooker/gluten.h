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

struct gluten_ref_data {
	char name[REF_NAMEMAX];
	struct gluten_offset offset;
	size_t len;
};

struct gluten_ctx {
	struct gluten_offset ip;
	struct gluten_offset lr;
	struct gluten_offset cp;
	struct gluten_offset dp;

	struct gluten g;

	struct gluten_arg_data match_dst[CALL_ARGS];
	struct gluten_arg_data call_src[CALL_ARGS];

	struct gluten_ref_data refs[REFS_MAX];
};

struct gluten_offset gluten_alloc(struct gluten_ctx *g, size_t size);
struct gluten_offset gluten_alloc_type(struct gluten_ctx *g, enum type type);
void gluten_init(struct gluten_ctx *g);
void gluten_block_init(struct gluten_ctx *g);

extern size_t gluten_size[TYPE_COUNT];

#endif /* GLUTEN_H */

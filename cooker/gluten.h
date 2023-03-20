/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef GLUTEN_H
#define GLUTEN_H

struct gluten_arg_data {
	int offset;
	size_t len;
};

struct gluten_ref_data {
	int name;
	int offset;
	size_t len;
};

struct gluten_ctx {
	int ip;
	int lr;
	int sp;
	char *gluten;

	struct gluten_arg_data match_dst[CALL_ARGS];
	struct gluten_arg_data call_src[CALL_ARGS];

	struct gluten_ref_data refs[REFS_MAX];
};

int gluten_alloc(struct gluten_ctx *g, size_t size);
int gluten_alloc_type(struct gluten_ctx *g, enum arg_type type);
int gluten_init(struct gluten_ctx *g);

#endif /* GLUTEN_H */

/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef EMIT_H
#define EMIT_H

void emit_nr(struct gluten_ctx *g, long number);
void emit_load(struct gluten_ctx *g, struct gluten_offset dst,
	       int index, size_t len);
void emit_cmp(struct gluten_ctx *g, enum op_cmp_type cmp,
	      struct gluten_offset x, struct gluten_offset y, size_t size,
	      enum jump_type jmp);
void emit_cmp_field(struct gluten_ctx *g, enum op_cmp_type cmp,
		    struct field *field,
		    struct gluten_offset base, struct gluten_offset match,
		    enum jump_type jmp);
struct gluten_offset emit_data(struct gluten_ctx *g, enum type type,
			       union value *value);

#endif /* EMIT_H */

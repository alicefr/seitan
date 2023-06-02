/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef EMIT_H
#define EMIT_H

void emit_nr(struct gluten_ctx *g, struct gluten_offset number);
void emit_call(struct gluten_ctx *g, struct ns_spec *ns, long nr,
	       unsigned count, bool is_ptr[6],
	       struct gluten_offset offset[6], struct gluten_offset ret_offset);
void emit_load(struct gluten_ctx *g, struct gluten_offset dst,
	       int index, size_t len);
void emit_cmp(struct gluten_ctx *g, enum op_cmp_type cmp,
	      struct gluten_offset x, struct gluten_offset y, size_t size,
	      enum jump_type jmp);
void emit_cmp_field(struct gluten_ctx *g, enum op_cmp_type cmp,
		    struct field *field,
		    struct gluten_offset base, struct gluten_offset match,
		    enum jump_type jmp);
void emit_return(struct gluten_ctx *g, struct gluten_offset v);
void emit_block(struct gluten_ctx *g, int32_t error);
void emit_copy(struct gluten_ctx *g,
	       struct gluten_offset dst, struct gluten_offset src, size_t size);
void emit_copy_field(struct gluten_ctx *g, struct field *field,
		     struct gluten_offset dst, struct gluten_offset src);
struct gluten_offset emit_data(struct gluten_ctx *g, enum type type,
			       size_t str_len, union value *value);
struct gluten_offset emit_data_at(struct gluten_ctx *g,
				  struct gluten_offset offset,
				  enum type type, union value *value);
struct gluten_offset emit_data_or(struct gluten_ctx *g,
				  struct gluten_offset offset,
				  enum type type, union value *value);
void link_block(struct gluten_ctx *g);
void link_match(struct gluten_ctx *g);

#endif /* EMIT_H */

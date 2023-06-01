/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PARSE_H
#define PARSE_H

long long value_get_num(struct num *desc, JSON_Value *value);
void value_get(union desc desc, enum type type, JSON_Value *value,
	       union value *out);
struct field *select_field(struct gluten_ctx *g, int pos,
			   struct select *s, union value v);
void parse_file(struct gluten_ctx *g, const char *path);

#endif /* PARSE_H */

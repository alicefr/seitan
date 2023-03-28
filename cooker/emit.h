/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef EMIT_H
#define EMIT_H

int emit_nr(struct gluten_ctx *g, long number);
int emit_load(struct gluten_ctx *g, int offset, int index, size_t len);

#endif /* EMIT_H */

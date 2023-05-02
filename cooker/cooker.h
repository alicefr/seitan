/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef COOKER_H
#define COOKER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define REFS_MAX			256
#define REF_NAMEMAX			256
#define CALL_ARGS			6

struct num;
struct field;
struct select;

union desc {
	struct num		*d_num;
	struct field		*d_struct;
	struct select		*d_select;
};

union value {
	int			v_int;
	uint32_t		v_u32;
	long long		v_num;
};

enum type {
	INT,
	INTMASK,
	INTFLAGS,

	U32,
	U32MASK,
	U32FLAGS,

	LONG,
	LONGMASK,
	LONGFLAGS,

	STRING,

	STRUCT,
	SELECT,

	PID,

	PORT,
	IPV4,
	IPV6,

	FDPATH,

	TYPE_END,
};

#define TYPE_COUNT		(TYPE_END - 1)

#define TYPE_IS_COMPOUND(t)	((t) == STRUCT || (t) == SELECT)
#define TYPE_IS_NUM(t)		((t) == INT || (t) == U32 || (t) == LONG)

enum jump_type {
	NEXT_BLOCK,
	END,
};

struct num {
	char *name;
	long long value;
};

struct field {
	char *name;
	enum type type;
	off_t offset;

	size_t strlen;

	union desc desc;
};

struct select_num {
	long long value;

	enum type type;
	union desc desc;
};

struct select {
	struct field *field;

	union {
		struct select_num *d_num;
	} desc;
};

struct arg {
	int pos;
	char *name;

	enum type type;
	size_t size;

	union desc desc;
};

#endif /* COOKER_H */

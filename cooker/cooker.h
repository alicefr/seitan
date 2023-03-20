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

#define REFS_MAX			256
#define CALL_ARGS			6

struct arg_num;
struct arg_struct;
struct arg_select;

union arg_value {
	struct arg_num		*d_num;
	struct arg_struct	*d_struct;
	struct arg_select	*d_select;
};

enum arg_type {
	ARG_INT,
	ARG_INTMASK,
	ARG_INTFLAGS,

	ARG_U32,
	ARG_U32MASK,
	ARG_U32FLAGS,

	ARG_LONG,
	ARG_LONGMASK,
	ARG_LONGFLAGS,

	ARG_STRING,

	ARG_STRUCT,
	ARG_SELECT,

	ARG_PID,

	ARG_PORT,
	ARG_IPV4,
	ARG_IPV6,

	ARG_FDPATH,

	ARG_TYPE_END,
};

#define ARG_TYPE_COUNT		(ARG_TYPE_END - 1)

struct arg_num {
	char *name;
	long long value;
};

struct arg_struct {
	char *name;
	enum arg_type type;
	size_t offset;

	size_t strlen;

	union arg_value desc;
};

struct arg_select_num {
	long long value;

	enum arg_type type;
	union arg_value desc;
};

struct arg_select {
	struct arg_struct *field;

	union {
		struct arg_select_num *d_num;
	} desc;
};

struct arg {
	int pos;
	char *name;

	enum arg_type type;
	size_t size;

	union arg_value desc;
};

#endif /* COOKER_H */

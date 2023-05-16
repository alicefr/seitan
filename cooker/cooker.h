/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef COOKER_H
#define COOKER_H

#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define TAGS_MAX			256
#define CALL_ARGS			6

struct num;
struct field;
struct select;

/**
 * union desc - Description of lists of numbers, structs or selector fields
 * @d_num:	Pointer to a list of numbers and their labels
 * @d_struct:	Pointer to a struct description
 * @d_select:	Pointer to description of a selector
 */
union desc {
	struct num		*d_num;
	struct field		*d_struct;
	struct select		*d_select;
};

/**
 * union value - Represent a generic value used internally by cooker
 * @v_int:	Value of type int
 * @v_u32:	Value of type u32
 * @v_num:	Value of type long long, or any other numeric type
 * @v_str:	String, directly from JSON
 */
union value {
	int			v_int;
	uint32_t		v_u32;
	long long		v_num;
	const char		*v_str;
};

/**
 * enum type - Types of values for arguments and fields within arguments
 */
enum type {
	UNDEF = 0,
	NONE,

	INT,
	INTMASK,
	INTFLAGS,

	U32,
	U32MASK,
	U32FLAGS,

	U64,
	U64MASK,
	U64FLAGS,

	LONG,
	LONGMASK,
	LONGFLAGS,

	STRING,

	STRUCT,
	SELECT,
	SELECTED,

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

/**
 * struct num - A numeric value and its label
 * @name:	Label for numeric value
 * @value:	Numeric value
 */
struct num {
	char *name;
	long long value;
};

/**
 * struct field - Field inside a struct
 * @name:	Name of field
 * @type:	Type of field
 * @offset:	Offset of field within struct, in bytes
 * @strlen:	Length of string for string types, 0 otherwise
 * @desc:	Description of possible values for field, or linked struct
 */
struct field {
	char *name;
	enum type type;
	off_t offset;

	size_t strlen;

	union desc desc;
};

/**
 * struct select_target - Description of value selected by selector field
 * @type:	Type of value
 * @size:	Size to dereference for pointers, 0 otherwise
 * @desc:	Description for selected value
 */
struct select_target {
	enum type type;		/* TODO: Almost a struct arg? */
	size_t size;

	union desc desc;
};

/**
 * struct arg - Description of part of, or complete system call argument
 * @pos:	Index of argument in system call
 * @name:	JSON name used for matches and calls
 * @type:	Argument type
 * @size:	Size of pointed area if any, 0 otherwise
 * @desc:	Description of list of numbers, struct or selector field
 */
struct arg {
	int pos;
	char *name;

	enum type type;
	size_t size;

	union desc desc;
};

/**
 * struct select_num - List of possible selections based on numeric selector
 * @value:	Numeric value of the selector
 * @target:	Argument description defined by this selector
 */
struct select_num {
	long long value;

	struct arg target;
};

/**
 * struct select - Association between argument description and selected values
 * @field:	Description of argument operating the selection
 * @d_num:	List of possible selections
 */
struct select {
	struct field *field;

	union {
		struct select_num *d_num;
	} desc;
};

#endif /* COOKER_H */

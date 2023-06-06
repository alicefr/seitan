/* SPDX-License-Identifier: GPL-2.0-or-later
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
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <util.h>

#define TAGS_MAX			256
#define ATTRS_MAX			256
#define CALL_ARGS			6

struct num;
struct field;
struct select;
struct size;

/**
 * union desc - Description of lists of numbers, structs or selector fields
 * @d_num:	Pointer to a list of numbers and their labels
 * @d_struct:	Pointer to a struct description
 * @d_select:	Pointer to description of a selector
 * @d_arg_size:	Position of argument whose pointed length is described
 */
union desc {
	struct num		*d_num;
	struct field		*d_struct;
	struct select		*d_select;
	intptr_t		d_size;
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
	uint64_t		v_u64;
	long long		v_num;
	const char		*v_str;
};

/**
 * enum type - Types of values for arguments and fields within arguments
 */
enum type {
	UNDEF = 0,
	NONE,

	USHORT,
	INT,
	U32,
	U64,
	LONG,

	STRING,

	STRUCT,
	SELECT,
	SELECTED,

	PID,

	PORT,
	IPV4,
	IPV6,

	GNU_DEV_MAJOR,
	GNU_DEV_MINOR,

	FDPATH,

	TYPE_END,
};

enum flags {
	/* Mask field with all possible values, first */
	MASK	= BIT(1),
	/* Intersection of multiple bits */
	FLAGS	= BIT(2),
	/* Represent size of another argument */
	SIZE	= BIT(3),

	COPY_ON_CALL = BIT(4),

	/* Don't copy value from original call, but fill on return */
	RBUF	= BIT(5),
	/* Copy value from original call, ignore on return */
	WBUF	= BIT(6),
};

#define TYPE_COUNT		(TYPE_END - 1)

#define TYPE_IS_COMPOUND(t)						\
	((t) == STRUCT || (t) == SELECT)
#define TYPE_IS_NUM(t)							\
	((t) == USHORT || (t) == INT || (t) == U32 ||			\
	 (t) == U64 || (t) == LONG ||					\
	 (t) == GNU_DEV_MAJOR || (t) == GNU_DEV_MINOR)

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
 * struct field - Field inside argument or struct
 * @name:	Name of field
 * @type:	Type of field
 * @flags:	Modifier flags for type
 * @offset:	Offset of field within argument or struct, in bytes
 * @size:	Turns int into int *, char into string, humans into paperclips
 * @desc:	Description of possible values for field, or linked struct
 */
struct field {
	char *name;
	enum type type;
	enum flags flags;

	off_t offset;

	size_t size;

	union desc desc;
};

/**
 * struct arg - Description of part of, or complete system call argument
 * @pos:	Index of argument in system call
 * @f:		Field describing part or complete argument
 */
struct arg {
	int pos;
	struct field f;
};

/**
 * struct select_num - List of possible selections based on numeric selector
 * @value:	Numeric value of the selector
 * @sel_size:	Size associated with selection (not necessarily argument size)
 * @target:	Argument description defined by this selector
 */
struct select_num {
	long long value;
	ssize_t sel_size;
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

enum attr_type {
	ATTR_NONE = 0,
	ATTR_SIZE,
};

/**
 * struct attr - Generic attribute for syscall model with link
 * @id:		Link
 * @v:		Attribute value
 */
struct attr {
	enum attr_type type;
	intptr_t id;
	union value v;
};

#endif /* COOKER_H */

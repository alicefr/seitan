/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Authors: Alice Frosi <afrosi@redhat.com>
 *	    Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef COMMON_GLUTEN_H
#define COMMON_GLUTEN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/seccomp.h>

#include "util.h"

extern struct seccomp_data anonymous_seccomp_data;

#define HEADER_SIZE		4096
#define INST_SIZE		4096
#define RO_DATA_SIZE		4096
#define DATA_SIZE		4096

#define INST_MAX		16
#define OFFSET_MAX		MAX(MAX(MAX(DATA_SIZE, RO_DATA_SIZE),	\
					INST_MAX),			\
				    ARRAY_SIZE(anonymous_seccomp_data.args))

enum gluten_offset_type {
	OFFSET_RO_DATA		= 0,
	OFFSET_DATA		= 1,
	OFFSET_SECCOMP_DATA	= 2,
	OFFSET_INSTRUCTION	= 3,
	OFFSET_TYPE_MAX		= OFFSET_INSTRUCTION,
};

struct gluten_offset {
#ifdef __GNUC__
	enum gluten_offset_type type:BITS_PER_NUM(OFFSET_TYPE_MAX);
#else
	uint16_t		type:BITS_PER_NUM(OFFSET_TYPE_MAX);
#endif
	uint16_t		offset:BITS_PER_NUM(OFFSET_MAX);
};

BUILD_BUG_ON(BITS_PER_NUM(OFFSET_TYPE_MAX) + BITS_PER_NUM(OFFSET_MAX) > 16)

enum ns_spec_type {
	NS_NONE,
	NS_SPEC_TARGET,
	NS_SPEC_PID,
	NS_SPEC_PATH,
};

struct ns_spec {
	enum ns_spec_type type;
	union {
		pid_t pid;
		char *path;
	} id;
};

/*
 * enum ns_type - Type of namespaces
 */
enum ns_type {
	NS_CGROUP,
	NS_IPC,
	NS_NET,
	NS_MOUNT,
	NS_PID,
	NS_TIME,
	NS_USER,
	NS_UTS,
};

/*
 * struct op_context - Description of the context where the call needs to be executed
 * @ns:	Descrption of the each namespace where the call needs to be executed
 */
struct op_context {
	struct ns_spec ns[sizeof(enum ns_type)];
};

enum op_type {
	OP_CALL,
	OP_BLOCK,
	OP_CONT,
	OP_INJECT,
	OP_INJECT_A,
	OP_RETURN,
	OP_LOAD,
	OP_END,
	OP_CMP,
	OP_RESOLVEDFD,
};

enum value_type {
	IMMEDIATE,
	REFERENCE,
};

struct op_nr {
	long nr;
	struct gluten_offset no_match;
};

struct op_call {
	long nr;
	bool has_ret;
	void *args[6];
	struct op_context context;
	struct gluten_offset ret;
};

struct op_block {
	int32_t error;
};

struct op_continue {
	bool cont;
};

struct op_return {
	struct gluten_offset val;
};

struct op_inject {
	struct gluten_offset new_fd;
	struct gluten_offset old_fd;
};

struct copy_arg {
	uint16_t args_off;
	enum value_type type;
	size_t size;
};

struct op_load {
	struct gluten_offset src;
	struct gluten_offset dst;
	size_t size;
};

enum op_cmp_type {
	CMP_EQ,
	CMP_NE,
	CMP_GT,
	CMP_GE,
	CMP_LT,
	CMP_LE,
};

struct op_cmp {
	struct gluten_offset x;
	struct gluten_offset y;
	size_t size;
	enum op_cmp_type cmp;
	unsigned int jmp;
};

struct op_resolvedfd {
	uint16_t fd_off;
	uint16_t path_off;
	size_t path_size;
	unsigned int jmp;
};

struct op {
	enum op_type type;
	union {
		struct op_nr nr;
		struct op_call call;
		struct op_block block;
		struct op_continue cont;
		struct op_return ret;
		struct op_inject inject;
		struct op_load load;
		struct op_cmp cmp;
		struct op_resolvedfd resfd;
	} op;
};

#ifdef COOKER
# define GLUTEN_CONST
#else
# define GLUTEN_CONST const
#endif

struct gluten {
	GLUTEN_CONST char header[HEADER_SIZE];

	GLUTEN_CONST char inst[INST_SIZE];

	GLUTEN_CONST char ro_data[RO_DATA_SIZE];

	char data[DATA_SIZE];
} __attribute__((packed));

BUILD_BUG_ON(INST_SIZE < INST_MAX * sizeof(struct op))

#ifdef COOKER
static inline void *gluten_ptr(struct gluten *g, const struct gluten_offset x)
#else
static inline void *gluten_write_ptr(struct gluten *g,
				     const struct gluten_offset x)
#endif
{
	/* TODO: Boundary checks */

	switch (x.type) {
	case OFFSET_DATA:
		return (char *)g->data + x.offset;
#ifdef COOKER
	case OFFSET_RO_DATA:
		return (char *)g->ro_data + x.offset;
	case OFFSET_INSTRUCTION:
		return (struct op *)(g->inst) + x.offset;
#endif
	default:
		return NULL;
	}
}

#ifndef COOKER
static inline const void *gluten_ptr(const struct seccomp_data *s,
				     struct gluten *g,
				     const struct gluten_offset x)
{
	switch (x.type) {
	case OFFSET_DATA:
		return g->data + x.offset;
	case OFFSET_RO_DATA:
		return g->ro_data + x.offset;
	case OFFSET_SECCOMP_DATA:
		return (const uint64_t *)s->args + x.offset;
	case OFFSET_INSTRUCTION:
		return (const struct op *)(g->inst) + x.offset;
	default:
		return NULL;
	}
}
#endif

#endif /* COMMON_GLUTEN_H */

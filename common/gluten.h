/* SPDX-License-Identifier: GPL-3.0-or-later
* Copyright 2023 Red Hat GmbH
* Authors: Alice Frosi <afrosi@redhat.com>
*          Stefano Brivio <sbrivio@redhat.com>
*/

#ifndef COMMON_GLUTEN_H
#define COMMON_GLUTEN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/seccomp.h>

#include <stdio.h>

#include "util.h"

extern struct seccomp_data anonymous_seccomp_data;

#define HEADER_SIZE		4096
#define INST_SIZE		4096
#define RO_DATA_SIZE		4096
#define DATA_SIZE		4096

#define INST_MAX		16
#define OFFSET_MAX                                       \
	MAX(MAX(MAX(DATA_SIZE, RO_DATA_SIZE), INST_MAX), \
	    ARRAY_SIZE(anonymous_seccomp_data.args))

#define OP_EMPTY { .block = { -1 } }
#define NO_FIELD block

#define NS_NUM sizeof(enum ns_type)
#define GET_BIT(x, i) (((x) & (1UL << (i))) != 0)

enum gluten_offset_type {
	OFFSET_NULL		= 0,
	OFFSET_RO_DATA		= 1,
	OFFSET_DATA		= 2,
	OFFSET_SECCOMP_DATA	= 3,
	OFFSET_INSTRUCTION	= 4,
	OFFSET_TYPE_MAX		= OFFSET_INSTRUCTION,
};

extern const char *gluten_offset_name[OFFSET_TYPE_MAX + 1];

struct gluten_offset {
#ifdef __GNUC__
	enum gluten_offset_type type	:BITS_PER_NUM(OFFSET_TYPE_MAX);
#else
	uint32_t type			:BITS_PER_NUM(OFFSET_TYPE_MAX);
#endif
	uint32_t offset			:BITS_PER_NUM(OFFSET_MAX);
};

BUILD_BUG_ON(BITS_PER_NUM(OFFSET_TYPE_MAX) + BITS_PER_NUM(OFFSET_MAX) > 32)

enum ns_spec_type {
	NS_NONE,
	/* Read the pid from seccomp_data */
	NS_SPEC_TARGET,
	/* Read the pid from gluten */
	NS_SPEC_PID,
	NS_SPEC_PATH,
};

struct ns_spec {
	enum ns_spec_type type;
	/* Pid or path based on the type */
	struct gluten_offset id;
	size_t size;
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
	OP_END = 0,
	OP_NR,
	OP_CALL,
	OP_COPY,
	OP_BLOCK,
	OP_CONT,
	OP_INJECT,
	OP_INJECT_A,
	OP_RETURN,
	OP_LOAD,
	OP_CMP,
	OP_RESOLVEDFD,
};

struct op_nr {
	struct gluten_offset nr;
	struct gluten_offset no_match;
};

struct syscall_desc {
        unsigned nr : 9;
        unsigned arg_count : 3;
        unsigned has_ret : 1;
        unsigned arg_deref : 6;
        struct gluten_offset data[];
};

struct op_call {
        struct gluten_offset syscall;
        struct gluten_offset context;
};

struct op_block {
	int32_t error;
};

struct op_return {
	struct gluten_offset val;
};

struct op_inject {
	struct gluten_offset new_fd;
	struct gluten_offset old_fd;
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
	struct gluten_offset jmp;
};

struct op_resolvedfd {
	struct gluten_offset fd;
	struct gluten_offset path;
	size_t path_size;
	unsigned int jmp;
};

struct op_copy {
	struct gluten_offset src;
	struct gluten_offset dst;
	size_t size;
};

struct op {
	enum op_type type;
	union {
		struct op_nr nr;
		struct op_call call;
		struct op_block block;
		struct op_return ret;
		struct op_inject inject;
		struct op_load load;
		struct op_cmp cmp;
		struct op_resolvedfd resfd;
		struct op_copy copy;
	} op;
};

#if defined(COOKER) || defined(SEITAN_TEST)
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

static inline bool is_offset_valid(const struct gluten_offset x)
{
	switch (x.type) {
	case OFFSET_NULL:
		return false;
	case OFFSET_DATA:
		return x.offset < DATA_SIZE;
	case OFFSET_RO_DATA:
		return x.offset < RO_DATA_SIZE;
	case OFFSET_INSTRUCTION:
		return x.offset < INST_SIZE;
	case OFFSET_SECCOMP_DATA:
		return x.offset < 6;
	default:
		return false;
	}
}

#ifdef COOKER
static inline void *gluten_ptr(struct gluten *g, const struct gluten_offset x)
#else
static inline void *gluten_write_ptr(struct gluten *g,
				     const struct gluten_offset x)
#endif
{
	if (!is_offset_valid(x))
		return NULL;

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
	if (!is_offset_valid(x))
		return NULL;

	if (x.type == OFFSET_SECCOMP_DATA && s == NULL)
		return NULL;

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

static inline bool check_gluten_limits(struct gluten_offset v, size_t size)
{
	struct gluten_offset off = { v.type, v.offset + size };
	if (is_offset_valid(off))
		return true;

	err("  offset limits are invalid");
	return false;
}

static inline int gluten_write(struct gluten *g, struct gluten_offset dst,
			       const void *src, size_t size)
{
	void *p = gluten_write_ptr(g, dst);
	if (p == NULL || !check_gluten_limits(dst, size))
		return -1;
	memcpy(p, src, size);

	return 0;
}

static inline int gluten_read(const struct seccomp_data *s, struct gluten *g,
			      void *dst, const struct gluten_offset src,
			      size_t size)
{
	const void *p = gluten_ptr(s, g, src);
	if (p == NULL || !check_gluten_limits(src, size))
		return -1;
	memcpy(dst, p, size);

	return 0;
}

#endif
#endif /* COMMON_GLUTEN_H */

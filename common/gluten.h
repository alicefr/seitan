#ifndef GLUTEN_H
#define GLUTEN_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_FD_INJECTED 10

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
	};
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
	OP_COPY_ARGS,
	OP_END,
	OP_CMP,
	OP_RESOLVEDFD,
};

enum value_type {
	IMMEDIATE,
	REFERENCE,
};

struct op_call {
	long nr;
	bool has_ret;
	void *args[6];
	struct op_context context;
	uint16_t ret_off;
};

struct op_block {
	int32_t error;
};

struct op_continue {
	bool cont;
};

struct op_return {
	enum value_type type;
	union {
		int64_t value;
		uint16_t value_off;
	};
};

struct fd_type {
	enum value_type type;
	union {
		uint32_t fd;
		uint16_t fd_off;
	};
};

struct op_inject {
	struct fd_type newfd;
	struct fd_type oldfd;
};

struct copy_arg {
	uint16_t args_off;
	enum value_type type;
	size_t size;
};

struct op_copy_args {
	struct copy_arg args[6];
};

struct op_cmp {
	uint16_t s1_off;
	uint16_t s2_off;
	size_t size;
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
		struct op_call call;
		struct op_block block;
		struct op_continue cont;
		struct op_return ret;
		struct op_inject inj;
		struct op_copy_args copy;
		struct op_cmp cmp;
		struct op_resolvedfd resfd;
	};
};
#endif /* GLUTEN_H */
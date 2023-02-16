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
 * struct act_context - Description of the context where the call needs to be executed
 * @ns:	Descrption of the each namespace where the call needs to be executed
 */
struct act_context {
	struct ns_spec ns[sizeof(enum ns_type)];
};

enum action_type {
	A_CALL,
	A_BLOCK,
	A_CONT,
	A_INJECT,
	A_INJECT_A,
	A_RETURN,
};

struct act_call {
	long nr;
	void *args[6];
	struct act_context context;
};

struct act_block {
	int32_t error;
};

struct act_continue {
	bool cont;
};

struct act_return {
	int64_t value;
};

struct act_inject {
	uint32_t newfd;
	uint32_t oldfd;
};

struct action {
	enum action_type type;
	union {
		struct act_call call;
		struct act_block block;
		struct act_continue cont;
		struct act_return ret;
		struct act_inject inj;
	};
};
#endif /* GLUTEN_H */

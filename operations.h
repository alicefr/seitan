#ifndef ACIONS_H
#define ACTIONS_H

#include <errno.h>

#define STACK_SIZE (1024 * 1024 / 8)
#define NS_NUM (sizeof(enum ns_type))

struct arg_clone {
	const struct op_call *args;
	pid_t pid;
	long ret;
	int err;
};

int do_call(struct arg_clone *c);
int do_operations(void *data, struct op operations[], unsigned int n_operations,
	       int tpid, int notifyfd, uint64_t id);
#endif /* ACTIONS_H */

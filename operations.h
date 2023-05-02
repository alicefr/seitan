/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#ifndef ACIONS_H
#define ACTIONS_H

#include <errno.h>
#include <linux/seccomp.h>

#include "common/gluten.h"
#include "common/util.h"

#define STACK_SIZE (1024 * 1024 / 8)
#define NS_NUM (sizeof(enum ns_type))
#define HANDLE_OP(code, call, type)                                     \
	case code:                                                      \
		do {                                                    \
			int res = call(req, notifier, g, &op->op.type); \
			if (res == 0)                                   \
				(op)++;                                 \
			else if (res == -1)                             \
				(op) = NULL;                            \
			else                                            \
				(op) += res;                            \
		} while (0);                                            \
		break

struct arg_clone {
	const struct op_call *args;
	pid_t pid;
	long ret;
	int err;
};

int do_call(struct arg_clone *c);
void eval(struct gluten *g, struct op *ops, const struct seccomp_notif *req,
	  int notifier);
int op_call(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_call *op);
int op_block(const struct seccomp_notif *req, int notifier, struct gluten *g,
	     struct op_block *op);
int op_return(const struct seccomp_notif *req, int notifier, struct gluten *g,
	      struct op_return *op);
int op_continue(const struct seccomp_notif *req, int notifier, struct gluten *g,
		void *);
int op_inject(const struct seccomp_notif *req, int notifier, struct gluten *g,
	      struct op_inject *op);
int op_inject_a(const struct seccomp_notif *req, int notifier, struct gluten *g,
		struct op_inject *op);
int op_cmp(const struct seccomp_notif *req, int notifier, struct gluten *g,
	   struct op_cmp *op);
int op_resolve_fd(const struct seccomp_notif *req, int notifier,
		  struct gluten *g, struct op_resolvedfd *op);
int op_load(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_load *load);
#endif /* ACTIONS_H */

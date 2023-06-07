/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#ifndef ACIONS_H
#define ACTIONS_H

#include <limits.h>
#include <errno.h>
#include <linux/seccomp.h>

#include "common/gluten.h"
#include "common/util.h"

#define STACK_SIZE (1024 * 1024 / 8)
#define HANDLE_OP(code, call, type, g)                                  \
	case code:                                                      \
		do {                                                    \
			struct op *start = (struct op *)g->inst;        \
			int res = call(req, notifier, g, &op->op.type); \
			if (res == 0)                                   \
				(op)++;                                 \
			else if (res == -1)                             \
				return -1;                              \
			else                                            \
				(op) = start + res;                     \
		} while (0);                                            \
		break

struct ns_path {
	char path[PATH_MAX];
};

struct arg_clone {
	long nr;
	const void *args[6];
	char ns_path[NS_TYPE_MAX + 1][PATH_MAX];
	long ret;
	int err;
};

int do_call(struct arg_clone *c);
int eval(struct gluten *g, const struct seccomp_notif *req, int notifier);
int op_call(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_call *op);
int op_return(const struct seccomp_notif *req, int notifier, struct gluten *g,
	      struct op_return *op);
int op_bitwise(const struct seccomp_notif *req, int notifier, struct gluten *g,
	       struct op_bitwise *op);
int op_cmp(const struct seccomp_notif *req, int notifier, struct gluten *g,
	   struct op_cmp *op);
int op_resolve_fd(const struct seccomp_notif *req, int notifier,
		  struct gluten *g, struct op_resolvefd *op);
int op_load(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_load *load);
int op_copy(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_copy *op);
int op_fd(const struct seccomp_notif *req, int notifier, struct gluten *g,
	  struct op_fd *op);
#endif /* ACTIONS_H */

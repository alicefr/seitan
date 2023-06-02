/* SPDX-License-Identifier: GPL-3.0-or-later
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
#define HANDLE_OP(code, call, type)                                     \
	case code:                                                      \
		do {                                                    \
			int res = call(req, notifier, g, &op->op.type); \
			if (res == 0)                                   \
				(op)++;                                 \
			else if (res == -1)                             \
				return -1;                              \
			else                                            \
				(op) += res;                            \
		} while (0);                                            \
		break

struct ns_path {
	char path[PATH_MAX];
};

struct arg_clone {
	long nr;
	void *args[6];
	char ns_path[NS_TYPE_MAX + 1][PATH_MAX];
	long ret;
	int err;
};

int do_call(struct arg_clone *c);
int eval(struct gluten *g, const struct seccomp_notif *req, int notifier);
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
int op_copy(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_copy *op);
#endif /* ACTIONS_H */

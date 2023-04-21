/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#ifndef ACIONS_H
#define ACTIONS_H

#include <errno.h>
#include <linux/seccomp.h>

#define STACK_SIZE (1024 * 1024 / 8)
#define NS_NUM (sizeof(enum ns_type))

struct arg_clone {
	const struct op_call *args;
	pid_t pid;
	long ret;
	int err;
};

int do_call(struct arg_clone *c);
int do_operations(void *data, struct op operations[], struct seccomp_notif *req,
		  unsigned int n_operations, int notifyfd);
#endif /* ACTIONS_H */

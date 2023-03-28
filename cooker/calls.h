/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef CALLS_H
#define CALLS_H

/**
 * struct call - Description of one known system call
 * @number:	Number from __NR_ macros, architecture dependent
 * @name:	Name for use in recipes
 * @args:	NULL-terminated array of argument descriptions
 */
struct call {
	long number;
	const char *name;
	struct arg *args;
};

extern struct call *call_sets[];

#endif /* CALLS_H */

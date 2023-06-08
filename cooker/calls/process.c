// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/calls/process.c - Description of known process-related system calls
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/*
clone
fork
vfork
execve
exit
wait3
wait4
waitid
kill
exit_group
unshare
kcmp
clone3
*/

#include <asm-generic/unistd.h>
#include <sys/syscall.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <sched.h>
#include <linux/kcmp.h>
#include <sys/wait.h>

#include "../cooker.h"
#include "../calls.h"

static struct num unshare_flags[] = {
	{ "CLONE_FILES",	CLONE_FILES },
	{ "CLONE_FS",		CLONE_FS },
	{ "CLONE_NEWCGROUP",	CLONE_NEWCGROUP },
	{ "CLONE_NEWIPC",	CLONE_NEWIPC },
	{ "CLONE_NEWNET",	CLONE_NEWNET },
	{ "CLONE_NEWNS",	CLONE_NEWNS },
	{ "CLONE_NEWPID",	CLONE_NEWPID },
	{ "CLONE_NEWTIME",	CLONE_NEWTIME },
	{ "CLONE_NEWUSER",	CLONE_NEWUSER },
	{ "CLONE_NEWUTS",	CLONE_NEWUTS },
	{ "CLONE_SYSVSEM",	CLONE_SYSVSEM },
	{ 0 }
};

static struct arg unshare_args[] = {
	{ 0,
		{
			"flags",	INT,	FLAGS, 0,	0,
			{ .d_num = unshare_flags }
		}
	}
};

struct call syscalls_process[] = {
	{ __NR_unshare, "unshare", unshare_args },
	{ 0 }
};

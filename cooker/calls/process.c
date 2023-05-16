// SPDX-License-Identifier: GPL-3.0-or-later

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

#include <unistd.h>
#include <sched.h>
#include <linux/kcmp.h>
#include <sys/wait.h>

#include "../cooker.h"
#include "../calls.h"

static struct arg unshare_args[] = {
	{
		0,	"flags",	INTFLAGS,	0,
		{ 0 /* TODO */ }
	},
};

struct call syscalls_process[] = {
	{ __NR_unshare, "unshare", unshare_args },
	{ 0 },
};

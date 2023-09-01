/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sched.h>

#include "../cooker.h"
#include "../calls.h"

static struct num sched_policy[] = {
	{ "SCHED_OTHER", SCHED_OTHER },
	{ "SCHED_BATCH", SCHED_BATCH },
	{ "SCHED_IDLE", SCHED_IDLE },
	{ "SCHED_FIFO", SCHED_FIFO },
	{ "SCHED_RR", SCHED_RR },
	{ "SCHED_RESET_ON_FORK", SCHED_RESET_ON_FORK }, /* ORed in policy */
	{ 0 },
};

static struct field sched_param[] = {
	{ "priority",
	  INT,
	  0,
	  offsetof(struct sched_param, sched_priority),
	  sizeof(int),
	  { 0 } },
	{ 0 },
};

static struct arg sched_setscheduler_args[] = {
	{ 0, { "pid", PID, 0, 0, 0, { 0 } } },
	{ 1, { "policy", INT, FLAGS, 0, 0, { .d_num = sched_policy } } },
	{ 2, { "param", STRUCT, 0, 0, 0, { .d_struct = sched_param } } }
};

struct call syscalls_scheduler[] = {
	{ __NR_sched_setscheduler, "sched_setscheduler", sched_setscheduler_args },
	{ 0 },
};

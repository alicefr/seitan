// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/calls.c - Known syscall sets
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "cooker.h"
#include "calls.h"

#include "calls/net.h"
#include "calls/ioctl.h"
#include "calls/process.h"
#include "calls/fs.h"

struct call *call_sets[] = {
	syscalls_net, syscalls_ioctl, syscalls_process, syscalls_fs, NULL,
};

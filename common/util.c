// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/util.c - Convenience routines
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <bits/local_lim.h>	/* TODO: Why isn't __USE_POSIX with limits.h
				 * enough for LOGIN_NAME_MAX here?
				 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/syscall.h>

#include "gluten.h"

#define logfn(name)							\
void name(const char *format, ...) {					\
	va_list args;							\
									\
	va_start(args, format);						\
	(void)vfprintf(stderr, format, args); 				\
	va_end(args);							\
	if (format[strlen(format)] != '\n')				\
		fprintf(stderr, "\n");					\
}

logfn(err)
logfn(info)
logfn(debug)

const char *gluten_offset_name[OFFSET_TYPE_MAX + 1] = {
	"NULL",
	"read-only data", "temporary data", "seccomp data",
	"instruction area", "metadata",
};

const char *context_type_name[CONTEXT_TYPE_MAX + 1] = {
	"mnt", "cgroup", "uts", "ipc", "user", "pid", "net", "time",
	"cwd",
	"uid", "gid",
};

const char *context_spec_type_name[CONTEXT_SPEC_TYPE_MAX + 1] = {
	"none", "caller", "pid", "path",
};

const char *bitwise_type_str[BITWISE_MAX + 1] = { "&", "|" };

const char *cmp_type_str[CMP_MAX + 1] = {
        "EQ", "NE", "GT", "GE", "LT", "LE",
};

const char *metadata_type_str[METADATA_MAX + 1] = { "uid", "gid" };
const char *syscall_name_str[N_SYSCALL + 1] = {
	[__NR_chown] 	= "chown",
	[__NR_connect] 	= "connect",
	[__NR_ioctl]	= "ioctl",
	[__NR_lchown] 	= "lchown",
	[__NR_mknod] 	= "mknod",
	[__NR_mknodat] 	= "mknodat",
	[__NR_read] 	= "read",
	[__NR_socket] 	= "socket",
	[__NR_unshare]	= "unshare",
        [__NR_open] 	= "open",

};

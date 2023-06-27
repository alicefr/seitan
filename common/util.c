// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/util.c - Convenience routines
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

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
	"read-only data", "temporary data", "seccomp data", "instruction area",
};

const char *context_type_name[CONTEXT_TYPE_MAX + 1] = {
	"mnt", "cgroup", "uts", "ipc", "user", "pid", "net", "time", "cwd",
};

const char *context_spec_type_name[CONTEXT_SPEC_TYPE_MAX + 1] = {
	"none", "caller", "pid", "path",
};

const char *bitwise_type_str[BITWISE_MAX + 1] = { "&", "|" };

const char *cmp_type_str[CMP_MAX + 1] = {
        "EQ", "NE", "GT", "GE", "LT", "LE",
};

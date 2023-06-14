// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/calls/io.c - Description of known input/output system calls
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/*
read
write
open
close

pread
pwrite
readv
writev
preadv
pwritev
copy_file_range
preadv2
pwritev2

openat2
*/

#include <asm-generic/unistd.h>
#include <sys/syscall.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/limits.h>

#include "../cooker.h"
#include "../calls.h"

static struct num open_flags[] = {
	{ "rdonly",	O_RDONLY },
	{ "wronly",	O_WRONLY },
	{ "rdwr",	O_RDWR },
	{ 0 },
};

static struct num open_modes[] = {
	{ "S_ISUID",	S_ISUID },
	{ "S_ISGID",	S_ISGID },
	{ "S_IRWXU",	S_IRWXU },
	{ "S_IRUSR",	S_IRUSR },
	{ "S_IWUSR",	S_IWUSR },
	{ "S_IXUSR",	S_IXUSR },
	{ "S_IRWXG",	S_IRWXG },
	{ "S_IRGRP",	S_IRGRP },
	{ "S_IWGRP",	S_IWGRP },
	{ "S_IXGRP",	S_IXGRP },
	{ "S_IRWXO",	S_IRWXO },
	{ "S_IROTH",	S_IROTH },
	{ "S_IWOTH",	S_IWOTH },
	{ "S_IXOTH",	S_IXOTH },
	{ "S_ISVTX",	S_ISVTX },
	{ 0 },
};

static struct arg read_args[] = {
	{ 0,
		{
			"fd",		INT,		0,	0,	0,
			{ 0 }
		}
	},
	{ 0,
		{
			"path",		FDPATH,		0,	0,	0,
			{ 0 }
		}
	},
	{ 1,
		{
			"buf",		STRING,		RBUF,	0,	BUFSIZ,
			{ 0 }
		}
	},
	{ 2,
		{
			"count",	LONG,		SIZE,	-1,	0,
			{ .d_size = (intptr_t)&read_args[1] }
		}
	},
	{ 0 },
};

static struct arg open_args[] = {
	{ 0,
		{
			"path",		STRING,			0,
			0,	PATH_MAX,
			{ 0 }
		}
	},
	{ 1,
		{
			"flags",	INT,	MASK | FLAGS,	0,	0,
			{ .d_num = open_flags }
		}
	},
	{ 2,
		{
			"mode",		INT,	MASK | FLAGS,	0,	0,
			{ .d_num = open_modes }
		}
	},
	{ 0 },
};

struct call syscalls_io[] = {
	{ __NR_read, "read", read_args },
	{ __NR_open, "open", open_args },
	{ 0 },
};

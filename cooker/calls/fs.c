// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/calls/fs.c - Description of known filesystem-related system calls
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/*
stat ?
fstat ?
lstat ?

lseek ?

fcntl ?
flock ~
fsync
fdatasync
truncate
ftruncate

getdents
getcwd
chdir
fchdir
mkdir
rmdir

rename

creat

link
unlink
symlink
readlink

chmod
fchmod
chown
fchown
fchownat
lchown
umask

mknod
mknodat

mount
umount2
swapon
swapoff
*/

#include <asm-generic/unistd.h>
#include <sys/syscall.h>

#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>

#include "../cooker.h"
#include "../calls.h"

static struct num modes[] = {
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

static struct num types[] = {
	{ "S_IFSOCK",	S_IFSOCK },
	{ "S_IFLNK",	S_IFLNK },
	{ "S_IFREG",	S_IFREG },
	{ "S_IFBLK",	S_IFBLK },
	{ "S_IFDIR",	S_IFDIR },
	{ "S_IFCHR",	S_IFCHR },
	{ "S_IFIFO",	S_IFIFO },
	{ 0 },
};

static struct arg mknod_args[] = {
	{ 0,
		{
			"path",		STRING,			0,
			0,	PATH_MAX,
			{ 0 }
		}
	},
	{ 1,
		{
			"mode",		INT,			FLAGS | MASK,
			0,	0,
			{ .d_num = modes },
		}
	},
	{ 1,
		{
			"type",		INT,			FLAGS | MASK,
			0,	0,
			{ .d_num = types },
		}
	},
	{ 2,
		{
			"major",	GNU_DEV_MAJOR,		0,
			0,	0,
			{ 0 },
		}
	},
	{ 2,
		{
			"minor",	GNU_DEV_MINOR,		0,
			0,	0,
			{ 0 },
		}
	},
	{ 0 }
};

static struct arg mknodat_args[] = {
	/* No dirfd: we only support absolute paths at the moment */
	{ 1,
		{
			"path",		STRING,			0,
			0,	PATH_MAX,
			{ 0 }
		}
	},
	{ 2,
		{
			"mode",		INT,			FLAGS | MASK,
			0,	0,
			{ .d_num = modes },
		}
	},
	{ 2,
		{
			"type",		INT,			FLAGS | MASK,
			0,	0,
			{ .d_num = types },
		}
	},
	{ 3,
		{
			"major",	GNU_DEV_MAJOR,		0,
			0,	0,
			{ 0 },
		}
	},
	{ 3,
		{
			"minor",	GNU_DEV_MINOR,		0,
			0,	0,
			{ 0 },
		}
	},
	{ 0 }
};

struct call syscalls_fs[] = {
	{ __NR_mknod, "mknod", mknod_args },
	{ __NR_mknodat, "mknodat", mknodat_args },
	{ 0 },
};

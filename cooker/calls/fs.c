// SPDX-License-Identifier: GPL-3.0-or-later

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

#include <fcntl.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "../cooker.h"
#include "../calls.h"

static struct arg mknod_args[] = {
	{
		0,	"path",		STRING,		1 /* TODO: PATH_MAX */,
		{ 0 }
	},
	{
		1,	"mode",		INTFLAGS,	0,
		{ 0 /* TODO */ },
	},
	{
		2,	"major",	UNDEF /* TODO */, 0,
		{ 0 },
	},
	{
		2,	"minor",	UNDEF /* TODO */, 0,
		{ 0 },
	},
	{ 0 },
};

struct call syscalls_fs[] = {
	{ __NR_mknod, "mknod", mknod_args },
	{ 0 },
};

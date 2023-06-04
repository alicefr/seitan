// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/calls/ioctl.c - Description of known ioctl(2) requests
 *
 * Copyright 2023 Red Hat GmbH
 * Authors: Alice Frosi <afrosi@redhat.com>
 *	    Stefano Brivio <sbrivio@redhat.com>
 */

/*
fd = ioctl_ns(fd, request)
n  = ioctl_tty(fd, cmd, argp)
e  = ioctl_iflags(fd, cmd, attr)
*/

#include <asm-generic/unistd.h>
#include <sys/syscall.h>

#include <sys/ioctl.h>
#include <termios.h>
#include <linux/fs.h>
#include <linux/nsfs.h>

#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "../cooker.h"
#include "../calls.h"

static struct num request[] = {
	{ "FS_IOC_GETFLAGS", FS_IOC_GETFLAGS },		/* ioctl_iflags */
	{ "FS_IOC_SETFLAGS", FS_IOC_SETFLAGS },

	{ "NS_GET_USERNS", NS_GET_USERNS },		/* ioctl_ns*/
	{ "NS_GET_PARENT", NS_GET_PARENT },

	{ "TCGETS", TCGETS },				/* ioctl_tty */
	{ "TCSETS", TCSETS },
	{ "TCSETSW", TCSETSW },
	{ "TCSETSF", TCSETSF },

	{ "TUNSETIFF", TUNSETIFF },			/* no man page? */

	{ 0 },
};

static struct num attr[] = {
	{ "FS_APPEND_FL", FS_APPEND_FL },
	{ "FS_COMPR_FL", FS_COMPR_FL },
	{ "FS_DIRSYNC_FL", FS_DIRSYNC_FL },
	{ "FS_IMMUTABLE_FL", FS_IMMUTABLE_FL },
	{ "FS_JOURNAL_DATA_FL", FS_JOURNAL_DATA_FL },
	{ "FS_NOATIME_FL", FS_NOATIME_FL },
	{ "FS_NOCOW_FL", FS_NOCOW_FL },
	{ "FS_NODUMP_FL", FS_NODUMP_FL },
	{ "FS_NOTAIL_FL", FS_NOTAIL_FL },
	{ "FS_PROJINHERIT_FL", FS_PROJINHERIT_FL },
	{ "FS_SECRM_FL", FS_SECRM_FL },
	{ "FS_SYNC_FL", FS_SYNC_FL },
	{ "FS_TOPDIR_FL", FS_TOPDIR_FL },
	{ "FS_UNRM_FL", FS_UNRM_FL },
};

static struct num tun_ifr_flags[] = {
	{ "IFF_TUN",	IFF_TUN },
	{ 0 },
};

static struct field tun_ifr[] = {	/* netdevice(7) */
	{
		"name",		STRING,	0,
		offsetof(struct ifreq, ifr_name),
		IFNAMSIZ,	{ 0 },
	},
	{
		"flags",	INT,	/* One allowed at a time? */ 0,
		offsetof(struct ifreq, ifr_flags),
		0,		{ .d_num = tun_ifr_flags },
	},
};

static struct select_num ioctl_request_arg[] = {
	{ FS_IOC_GETFLAGS,
		{ 2,
			{
				"argp",	INT,	FLAGS,
				sizeof(int),		0,
				{ .d_num = attr }
			}
		}
	},
	{ FS_IOC_SETFLAGS,
		{ 2,
			{
				"argp",	INT,	FLAGS,
				sizeof(int),		0,
				{ .d_num = attr }
			}
		}
	},
	{ TUNSETIFF,
		{ 2,
			{
				"ifr",	STRUCT,	0,
				sizeof(struct ifreq),	0,
				{ .d_struct = tun_ifr }
			}
		}
	},
	{ 0 },
};

static struct field ioctl_request = {
	"request", INT, 0, 0, 0, { .d_num = request },
};

static struct select ioctl_request_select = {
	&ioctl_request, { .d_num = ioctl_request_arg }
};

static struct arg ioctl_args[] = {
	{ 0,
		{
			"path",		FDPATH,		0,	0,	0,
			{ 0 }
		}
	},
	{ 0,
		{
			"fd",		INT,		0,	0,	0,
			{ 0 }
		}
	},
	{ 1,
		{
			"request",	SELECT,		0,	0,	0,
			{ .d_select = &ioctl_request_select }
		}
	},
	{ 2,
		{
			"arg",		SELECTED,	0,	-1,	0,
			{ 0 }
		}
	},
	{ 0 },
};

struct call syscalls_ioctl[] = {
	{ __NR_ioctl, "ioctl", ioctl_args },
	{ 0 },
};

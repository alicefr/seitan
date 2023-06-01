// SPDX-License-Identifier: GPL-3.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/calls/net.c - Description of known networking system calls
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/*
fd = socket(family, type stream/dgram/..., protocol)
fd = connect(fd, addr, addrlen)
fd = accept(fd, addr, addrlen)
n  = sendto(fd, buf, len, flags, dst addr, addrlen)
n  = recvfrom(fd, buf, len, flags, src addr, addrlen)
n  = sendmsg(fd, msg, flags)
n  = recvmsg(fd, msg, flags)
e  = shutdown(fd, rd/wr/rdwr)
e  = bind(fd, addr, addrlen)
e  = listen(fd, backlog)
e  = getsockname(fd, bound addr, addrlen)
e  = getpeername(fd, peer addr, addrlen)
e  = socketpair(family, type stream/dgram/..., sockets[2])
e  = setsockopt(fd, level, optname, *optval, optlen)
e  = getsockopt(fd, level, optname, *optval, *optlen)
n  = recvmmsg(fd, *msgvec, vlen, flags, *timeout)
n  = sendmmsg(fd, *msgvec, vlen, flags)
*/

#include <asm-generic/unistd.h>
#include <sys/syscall.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/un.h>
#include <linux/netlink.h>

#include "../cooker.h"
#include "../calls.h"

static struct num af[] = {
	{ "unix",	AF_UNIX },
	{ "ipv4",	AF_INET },
	{ "ipv6",	AF_INET6 },
	{ "netlink",	AF_NETLINK },
	{ "packet",	AF_PACKET },
	{ "vsock",	AF_VSOCK },
	{ 0 },
};

static struct num socket_types[] = {
	{ "stream",	SOCK_STREAM },
	{ "dgram",	SOCK_DGRAM },
	{ "seq",	SOCK_SEQPACKET },
	{ "raw",	SOCK_RAW },
	{ "packet",	SOCK_PACKET },
	{ 0 },
};

static struct num socket_flags[] = {
	{ "nonblock",	SOCK_NONBLOCK },
	{ "cloexec",	SOCK_CLOEXEC },
	{ 0 },
};

static struct num protocols[] = {
	{ "ip",		IPPROTO_IP },
	{ "icmp",	IPPROTO_ICMP },
	{ "igmp",	IPPROTO_IGMP },
	{ "tcp",	IPPROTO_TCP },
	{ "udp",	IPPROTO_UDP },
	{ "ipv6",	IPPROTO_IPV6 },
	{ "gre",	IPPROTO_GRE },
	{ "esp",	IPPROTO_ESP },
	{ "ah",		IPPROTO_AH },
	{ "sctp",	IPPROTO_SCTP },
	{ "udplite",	IPPROTO_UDPLITE },
	{ "mpls",	IPPROTO_MPLS },
	{ "raw",	IPPROTO_RAW },
	{ "mptcp",	IPPROTO_MPTCP },
	{ 0 },
};

static struct arg socket_args[] = {
	{ 0,
		{
			"family",	INT,	0,	0,	0,
			{ .d_num = af }
		}
	},
	{ 1,
		{
			"type",		INT,	MASK,	0,	0,
			{ .d_num = socket_types }
		}
	},
	{ 1,
		{
			"flags",	INT,	FLAGS,	0,	0,
			{ .d_num = socket_flags }
		}
	},
	{ 2,
		{
			"protocol",	INT,	0,	0,	0,
			{ .d_num = protocols }
		}
	},
	{ 0 },
};

static struct field connect_addr_unix[] = {
	{
		"path",		STRING,	0,
		offsetof(struct sockaddr_un, sun_path),
		UNIX_PATH_MAX,	{ 0 }
	},
	{ 0 },
};

static struct field connect_addr_ipv4[] = {
	{
		"port",		PORT,	0,
		offsetof(struct sockaddr_in, sin_port),
		0,		{ 0 }
	},
	{
		"addr",		IPV4,	0,
		offsetof(struct sockaddr_in, sin_addr),
		0,		{ 0 }
	},
	{ 0 },
};

static struct field connect_addr_ipv6[] = {
	{
		"port",		PORT,	0,
		offsetof(struct sockaddr_in6, sin6_port),
		0,		{ 0 }
	},
	{
		"addr",		IPV6,	0,
		offsetof(struct sockaddr_in6, sin6_addr),
		0,		{ 0 }
	},
	{ 0 },
};

static struct field connect_addr_nl[] = {
	{
		"pid",		PID,	0,
		offsetof(struct sockaddr_nl, nl_pid),
		0,		{ 0 }
	},
	{
		"groups",	U32,	0,
		offsetof(struct sockaddr_nl, nl_groups),
		0,		{ 0 }
	},
	{ 0 },
};

static struct field connect_family = {
	"family",	INT,	0,
	offsetof(struct sockaddr, sa_family),
	0,		{ .d_num = af }
};

static struct select_num connect_addr_select_family[] = {
	{ AF_UNIX,
		{ 1,
			{
				NULL, STRUCT, 0, 0, 0,
				{ .d_struct = connect_addr_unix }
			}
		}
	},
	{ AF_INET,
		{ 1,
			{
				NULL, STRUCT, 0, 0, 0,
				{ .d_struct = connect_addr_ipv4 }
			}
		}
	},
	{ AF_INET6,
		{ 1,
			{
				NULL, STRUCT, 0, 0, 0,
				{ .d_struct = connect_addr_ipv6 }
			}
		}
	},
	{ AF_NETLINK,
		{ 1,
			{
				NULL, STRUCT, 0, 0, 0,
				{ .d_struct = connect_addr_nl }
			}
		}
	},
	{ 0 },
};

static struct select connect_addr_select = {
	&connect_family, { .d_num = connect_addr_select_family }
};

static struct arg connect_args[] = {
	{ 0,
		{
			"fd",		INT,		0,
			0,
			0,
			{ 0 },
		},
	},
	{ 0,
		{
			"path",		FDPATH,		0,
			0,
			0,
			{ 0 },
		},
	},
	{ 1,
		{
			"addr",		SELECT,		0,
			0,
			sizeof(struct sockaddr_storage),
			{ .d_select = &connect_addr_select },
		},
	},
	{ 2,
		{
			"addrlen",	LONG,		SIZE,
			0,
			0,
			{ .d_arg_size = 1 },
		},
	},
};

struct call syscalls_net[] = {
	{ __NR_connect,		"connect",		connect_args },
	{ __NR_socket,		"socket",		socket_args },
	{ 0 },
};

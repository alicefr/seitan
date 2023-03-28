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

static struct arg_num af[] = {
	{ "unix",	AF_UNIX },
	{ "ipv4",	AF_INET },
	{ "ipv6",	AF_INET6 },
	{ "netlink",	AF_NETLINK },
	{ "packet",	AF_PACKET },
	{ "vsock",	AF_VSOCK },
	{ 0 },
};

static struct arg_num socket_types[] = {
	{ "stream",	SOCK_STREAM },
	{ "dgram",	SOCK_DGRAM },
	{ "seq",	SOCK_SEQPACKET },
	{ "raw",	SOCK_RAW },
	{ "packet",	SOCK_PACKET },
	{ 0 },
};

static struct arg_num socket_flags[] = {
	{ "nonblock",	SOCK_NONBLOCK },
	{ "cloexec",	SOCK_CLOEXEC },
	{ 0 },
};

static struct arg_num protocols[] = {
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
	{ 0, "family",		ARG_INT,	0, { .d_num = af } },
	{ 1, "type",		ARG_INTMASK,	0, { .d_num = socket_types } },
	{ 1, "flags",		ARG_INTFLAGS,	0, { .d_num = socket_flags } },
	{ 2, "protocol",	ARG_INT,	0, { .d_num = protocols } },
	{ 0 },
};

static struct arg_struct connect_addr_unix[] = {
	{ "path",	ARG_STRING,
		offsetof(struct sockaddr_un, sun_path),
		UNIX_PATH_MAX,		{ 0 }
	},
	{ 0 },
};

static struct arg_struct connect_addr_ipv4[] = {
	{ "port",	ARG_PORT,
		offsetof(struct sockaddr_in, sin_port),
		0,			{ 0 }
	},
	{ "addr",	ARG_IPV4,
		offsetof(struct sockaddr_in, sin_addr),
		0,			{ 0 }
	},
	{ 0 },
};

static struct arg_struct connect_addr_ipv6[] = {
	{ "port",	ARG_PORT,
		offsetof(struct sockaddr_in6, sin6_port),
		0,			{ 0 }
	},
	{ "addr",	ARG_IPV6,
		offsetof(struct sockaddr_in6, sin6_addr),
		0,			{ 0 }
	},
	{ 0 },
};

static struct arg_struct connect_addr_nl[] = {
	{ "pid",	ARG_PID,
		offsetof(struct sockaddr_nl, nl_pid),
		0,			{ 0 }
	},
	{ "groups",	ARG_U32,
		offsetof(struct sockaddr_in6, sin6_addr),
		0,			{ 0 }
	},
	{ 0 },
};

static struct arg_struct connect_family = {
	"family",	ARG_INT,
		offsetof(struct sockaddr, sa_family),
		0,			{ .d_num = af }
};

static struct arg_select_num connect_addr_select_family[] = {
	{ AF_UNIX,	ARG_STRUCT,	{ .d_struct = connect_addr_unix } },
	{ AF_INET,	ARG_STRUCT,	{ .d_struct = connect_addr_ipv4 } },
	{ AF_INET6,	ARG_STRUCT,	{ .d_struct = connect_addr_ipv6 } },
	{ AF_NETLINK,	ARG_STRUCT,	{ .d_struct = connect_addr_nl } },
	{ 0 },
};

static struct arg_select connect_addr_select = {
	&connect_family, { .d_num = connect_addr_select_family }
};

static struct arg connect_args[] = {
	{ 0, "fd",	ARG_INT,	0,
		{ 0 },
	},
	{ 0, "path",	ARG_FDPATH,	0,
		{ 0 },
	},
	{ 1, "addr",	ARG_SELECT,	sizeof(struct sockaddr_storage),
		{ .d_select = &connect_addr_select },
	},
	{ 2, "addrlen",	ARG_LONG,	0,
		{ 0 },
	},
};

struct call syscalls_net[] = {
	{ __NR_connect,		"connect",		connect_args },
	{ __NR_socket,		"socket",		socket_args },
	{ 0 },
};

// SPDX-License-Identifier: AGPL-3.0-or-later

/* SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * seitan.c - Wait for processes, listen for syscalls, handle them
 *
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static int nl_init(void)
{
	int s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
				  .nl_groups = CN_IDX_PROC,
				  .nl_pid = getpid(),
				};
	struct req_t {
		struct nlmsghdr nlh;
		struct cn_msg cnm;
		enum proc_cn_mcast_op mop;
	} __attribute__ ((packed, aligned(NLMSG_ALIGNTO))) req = {
		.nlh.nlmsg_type		= NLMSG_DONE,
		.nlh.nlmsg_pid		= getpid(),

		.cnm.id.idx		= CN_IDX_PROC,
		.cnm.id.val		= CN_VAL_PROC,
		.cnm.len		= sizeof(enum proc_cn_mcast_op),

		.mop			= PROC_CN_MCAST_LISTEN,
	};

	bind(s, (struct sockaddr *)&sa, sizeof(sa));

	req.nlh.nlmsg_len = sizeof(req);
	send(s, &req, sizeof(req), 0);

	return s;
}

static int event(int s)
{
	char path[PATH_MAX + 1], exe[PATH_MAX + 1];
	struct proc_event *ev;
	struct nlmsghdr *nlh;
	struct cn_msg *cnh;
	char buf[BUFSIZ];
	ssize_t n;

	if ((n = recv(s, &buf, sizeof(buf), 0)) <= 0)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	for (; NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n)) {
		if (nlh->nlmsg_type == NLMSG_NOOP)
			continue;

		if ((nlh->nlmsg_type == NLMSG_ERROR) ||
		    (nlh->nlmsg_type == NLMSG_OVERRUN))
			break;

		cnh = NLMSG_DATA(nlh);
		ev = (struct proc_event *)cnh->data;

		if (ev->what != PROC_EVENT_EXEC)
			continue;

		snprintf(path, PATH_MAX, "/proc/%i/exe",
			 ev->event_data.exec.process_pid);

		readlink(path, exe, PATH_MAX);
		if (!strcmp(exe, "/usr/local/bin/seitan-loader") ||
		    !strcmp(exe, "/usr/bin/seitan-loader"))
			return ev->event_data.exec.process_pid;

		if (nlh->nlmsg_type == NLMSG_DONE)
			break;
	}

	return -EAGAIN;
}

enum transform {
	NONE,
	FD1_UNIX,
	FDRET_SRC,
	DEV_CHECK,
};

struct table {
	enum transform type;
	long number;

	char arg[6][1024];
};

static struct table t[16];

int handle(struct seccomp_notif *req, int notifyfd)
{
	char path[PATH_MAX + 1];
	struct sockaddr_un s_un;
	int fd_unix;
	unsigned i;
	int mem;

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		if (t[i].number == req->data.nr)
			break;
	}

	if (i == sizeof(t) / sizeof(t[0]))	/* Not found */
		return 1;

	if (t[i].type != FD1_UNIX)		/* Not implemented yet */
		return 1;

	/* FD1_UNIX here */
	snprintf(path, sizeof(path), "/proc/%i/mem", req->pid);
	fd_unix = req->data.args[0];

	mem = open(path, O_RDONLY);
	lseek(mem, req->data.args[1], SEEK_SET);
	read(mem, &s_un, sizeof(s_un));
	close(mem);

	if (!strcmp(s_un.sun_path, t[i].arg[0])) {
		int own_fd = socket(AF_UNIX, SOCK_STREAM, 0);

		struct seccomp_notif_addfd addfd = { .id = req->id,
			.flags = SECCOMP_ADDFD_FLAG_SEND | SECCOMP_ADDFD_FLAG_SETFD,
			.srcfd = own_fd, .newfd = fd_unix, };

		connect(own_fd, &s_un, sizeof(s_un));
		ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
		return 0;
	}

	return 1;
}

int main(int argc, char **argv)
{
	int s = nl_init(), ret, pidfd, notifier;
	char resp_b[BUFSIZ], req_b[BUFSIZ];
	struct seccomp_notif_resp *resp = (struct seccomp_notif_resp *)resp_b;
	struct seccomp_notif *req = (struct seccomp_notif *)req_b;
	int fd;

	fd = open("t.out", O_CLOEXEC | O_RDONLY);
	read(fd, t, sizeof(t));
	close(fd);

	if (argc < 2)
		while ((ret = event(s)) == -EAGAIN);
	else
		ret = atoi(argv[1]);

	if (ret < 0)
		exit(EXIT_FAILURE);

	if ((pidfd = syscall(SYS_pidfd_open, ret, 0)) < 0) {
		perror("pidfd_open");
		exit(EXIT_FAILURE);
	}

	sleep(1);

	if ((notifier = syscall(SYS_pidfd_getfd, pidfd, 3, 0)) < 0) {
		perror("pidfd_getfd");
		exit(EXIT_FAILURE);
	}

	while (1) {
		/* TODO: Open syscall transformation table blob, actually handle
		 * syscalls actions as parsed
		 */
		memset(req, 0, sizeof(*req));
		ioctl(notifier, SECCOMP_IOCTL_NOTIF_RECV, req);

		if (!handle(req, notifier))
			continue;

		resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		resp->id = req->id;
		resp->error = 0;
		resp->val = 0;

		ioctl(notifier, SECCOMP_IOCTL_NOTIF_SEND, resp);
	}
}

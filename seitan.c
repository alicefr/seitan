// SPDX-License-Identifier: AGPL-3.0-or-later

/* SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * src/seitan/seitan.c - Wait for processes, listen for syscalls, handle them
 *
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>, Alice Frosi <afrosi@redhat.com>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <argp.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "common.h"
#include "gluten.h"
#include "operations.h"
#include "util.h"

#define EPOLL_EVENTS 8

static char doc[] = "Usage: seitan: setain -pid <pid> -i <input file> ";

/* Seitan options */
static struct argp_option options[] = {
	{ "input", 'i', "FILE", 0, "Action input file", 0 },
	{ "output", 'o', "FILE", 0, "Log filtered syscall in the file", 0 },
	{ "pid", 'p', "pid", 0,
	  "Pid of process to monitor (cannot be used together with -socket)",
	  0 },
	{ "socket", 's', "/tmp/seitan.sock", 0,
	  "Socket to pass the seccomp notifier fd (cannot be used together with -pid)",
	  0 },
	{ 0 }
};

struct arguments {
	char *input_file;
	char *output_file;
	char *socket;
	int pid;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
	case 'p':
		arguments->pid = atoi(arg);
		break;
	case 'i':
		arguments->input_file = arg;
		break;
	case 'o':
		arguments->output_file = arg;
		break;
	case 's':
		arguments->socket = arg;
		break;
	case ARGP_KEY_END:
		if (arguments->input_file == NULL)
			argp_error(state, "missing input file");
		if (strcmp(arguments->socket, "") > 0 && arguments->pid > 0)
			argp_error(
				state,
				"the -socket and -pid options cannot be used together");
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { .options = options,
			    .parser = parse_opt,
			    .args_doc = NULL,
			    .doc = doc,
			    .children = NULL,
			    .help_filter = NULL,
			    .argp_domain = NULL };

static int nl_init(void)
{
	int s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = CN_IDX_PROC,
		.nl_pid = getpid(),
	};
	struct req_t {
		struct nlmsghdr nlh;
		struct cn_msg cnm;
		enum proc_cn_mcast_op mop;
	} __attribute__((packed, aligned(NLMSG_ALIGNTO))) req = {
		.nlh.nlmsg_type = NLMSG_DONE,
		.nlh.nlmsg_pid = getpid(),

		.cnm.id.idx = CN_IDX_PROC,
		.cnm.id.val = CN_VAL_PROC,
		.cnm.len = sizeof(enum proc_cn_mcast_op),

		.mop = PROC_CN_MCAST_LISTEN,
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
		if (!strcmp(exe, "/usr/local/bin/seitan-eater") ||
		    !strcmp(exe, "/usr/bin/seitan-eater"))
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

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
			     unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static void unblock_eater(int pidfd)
{
	if (pidfd_send_signal(pidfd, SIGCONT, NULL, 0) == -1) {
		perror("pidfd_send_signal");
		exit(EXIT_FAILURE);
	}
}

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

	if (i == sizeof(t) / sizeof(t[0])) /* Not found */
		return 1;

	if (t[i].type != FD1_UNIX) /* Not implemented yet */
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

		struct seccomp_notif_addfd addfd = {
			.id = req->id,
			.flags = SECCOMP_ADDFD_FLAG_SEND |
				 SECCOMP_ADDFD_FLAG_SETFD,
			.srcfd = own_fd,
			.newfd = fd_unix,
		};

		connect(own_fd, &s_un, sizeof(s_un));
		ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
		return 0;
	}

	return 1;
}

static int create_socket(const char *path)
{
	struct sockaddr_un addr;
	int ret, conn;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		die("  error creating UNIX socket");

	strcpy(addr.sun_path, path);
	addr.sun_family = AF_UNIX;
	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		die("  bind");

	ret = listen(fd, 1);
	if (ret < 0)
		die("  listen");
	conn = accept(fd, NULL, NULL);
	if (conn < 0)
		die("  accept");

	return conn;
}

static int recvfd(int sockfd)
{
	struct msghdr msgh;
	struct iovec iov;
	int data, fd;
	ssize_t nr;

	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} controlMsg;
	struct cmsghdr *cmsgp;

	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	iov.iov_base = &data;
	iov.iov_len = sizeof(int);

	msgh.msg_control = controlMsg.buf;
	msgh.msg_controllen = sizeof(controlMsg.buf);

	nr = recvmsg(sockfd, &msgh, 0);
	if (nr == -1)
		die("  recvmsg");

	cmsgp = CMSG_FIRSTHDR(&msgh);

	if (cmsgp == NULL || cmsgp->cmsg_len != CMSG_LEN(sizeof(int)) ||
	    cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS) {
		errno = EINVAL;
		return -1;
	}

	memcpy(&fd, CMSG_DATA(cmsgp), sizeof(int));
	return fd;
}

static int write_syscall(int fd, struct seccomp_notif *req)
{
	char buf[1000];

	/* TODO: Define format and print syscall with the right arguments */
	snprintf(buf, sizeof(buf), "nr_syscall=%d\n", req->data.nr);
	write(fd, buf, strlen(buf));
	return 0;
}

int main(int argc, char **argv)
{
	int s = nl_init(), ret, pidfd, notifier;
	char req_b[BUFSIZ];
	struct epoll_event ev, events[EPOLL_EVENTS];
	struct seccomp_notif *req = (struct seccomp_notif *)req_b;
	struct arguments arguments;
	char path[PATH_MAX + 1];
	bool running = true;
	bool output = false;
	int fd, epollfd;
	int notifierfd;
	int nevents, i;
	int fdout;

	arguments.pid = -1;
	argp_parse(&argp, argc, argv, 0, 0, &arguments);
	fd = open(arguments.input_file, O_CLOEXEC | O_RDONLY);
	read(fd, t, sizeof(t));
	close(fd);

	if (strcmp(arguments.output_file, "") > 0) {
		output = true;
		unlink(arguments.output_file);
		if ((fdout = open(arguments.output_file,
				  O_CREAT | O_RDWR | O_TRUNC)) < 0)
			die("  open");
	}

	if (arguments.pid > 0) {
		if ((pidfd = syscall(SYS_pidfd_open, arguments.pid, 0)) < 0)
			die("  pidfd_open");
		snprintf(path, sizeof(path), "/proc/%d/fd", arguments.pid);
		if ((notifierfd = find_fd_seccomp_notifier(path)) < 0)
			die("  failed getting fd of the notifier");
		if ((notifier = syscall(SYS_pidfd_getfd, pidfd, notifierfd,
					0)) < 0)
			die("  pidfd_getfd");
		/* Unblock seitan-loader */
		unblock_eater(pidfd);
	} else if (strcmp(arguments.socket, "") > 0) {
		unlink(arguments.socket);
		if ((fd = create_socket(arguments.socket)) < 0)
			exit(EXIT_FAILURE);
		if ((notifier = recvfd(fd)) < 0)
			exit(EXIT_FAILURE);
	} else {
		while ((ret = event(s)) == -EAGAIN)
			;
		if (ret < 0)
			exit(EXIT_FAILURE);
	}
	sleep(1);

	if ((epollfd = epoll_create1(0)) < 0) {
		perror("epoll_create");
		exit(EXIT_FAILURE);
	}
	ev.events = EPOLLIN;
	ev.data.fd = notifier;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, notifier, &ev) == -1) {
		perror("epoll_ctl: notifier");
		exit(EXIT_FAILURE);
	}

	while (running) {
		nevents = epoll_wait(epollfd, events, EPOLL_EVENTS, -1);
		if (nevents < 0) {
			perror("epoll_wait");
			exit(EXIT_FAILURE);
		}
		memset(req, 0, sizeof(*req));
		if (ioctl(notifier, SECCOMP_IOCTL_NOTIF_RECV, req) < 0)
			die("  recieving seccomp notification");
		for (i = 0; i < nevents; ++i) {
			if (events[i].events & EPOLLHUP) {
				/* The notifier fd was closed by the target */
				running = false;
			} else if (notifier == events[i].data.fd) {
				/*
				 * TODO: remove until we parse correctly the
				 * operations from the bytecode
				 */
				struct op operations[] = {
					{ .type = OP_CONT },
				};
				if (do_operations(NULL, operations, req,
						  sizeof(operations) /
							  sizeof(operations[0]),
						  req->pid, notifier,
						  req->id) == -1)
					die("  failed executing operation");

				if (output)
					write_syscall(fdout, req);
			}
		}
	}
	if (strcmp(arguments.socket, "") > 0)
		unlink(arguments.socket);
}

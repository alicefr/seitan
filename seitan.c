// SPDX-License-Identifier: AGPL-3.0-or-later

/* SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * seitan.c - Wait for processes, listen for syscalls, handle them
 *
 * Copyright (c) 2022 Red Hat GmbH
 * Authors: Alice Frosi <afrosi@redhat.com>
 * 	    Stefano Brivio <sbrivio@redhat.com>
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
#include <getopt.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/types.h>
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

/* Seitan options */
static struct option options[] = {
	{ "input", required_argument, NULL, 'i' },
	{ "pid", optional_argument, NULL, 'p' },
	{ "socket", optional_argument, NULL, 's' },
};

struct arguments {
	char *input_file;
	char *socket;
	int pid;
};

static void usage()
{
	printf("seitan: monitor for processes on seccomp events and executor for actions\n"
	       "Example:  setain -pid <pid> -i <input file>\n"
	       "Usage:\n"
	       "\t-i, --input:\tAction input file\n"
	       "\t-p, --pid:\tPid of process to monitor (cannot be used together with socket)\n"
	       "\t-s, --socket:\tSocket to pass the seccomp notifier fd (cannot be used together with pid)\n");
	exit(EXIT_FAILURE);
}

static void parse(int argc, char **argv, struct arguments *arguments)
{
	int option_index = 0;
	int oc;
	if (arguments == NULL)
		usage();
	while ((oc = getopt_long(argc, argv, ":i:o:p:s:", options,
				 &option_index)) != -1) {
		switch (oc) {
		case 'p':
			arguments->pid = atoi(optarg);
			break;
		case 'i':
			arguments->input_file = optarg;
			break;
		case 's':
			arguments->socket = optarg;
			break;
		default:
			usage();
		}
	}
	if (arguments->input_file == NULL) {
		err("missing input file");
		usage();
	}
	if (arguments->socket != NULL && arguments->pid > 0) {
		err("the socket and pid options cannot be used together");
		usage();
	}
	if (arguments->socket == NULL && arguments->pid < 0) {
		err("select one of the options between socket and pid");
		usage();
	}
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
			     unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static void unblock_eater(int pidfd)
{
	if (pidfd_send_signal(pidfd, SIGCONT, NULL, 0) == -1)
		die("  pidfd_send_signal");
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

int main(int argc, char **argv)
{
	char req_b[BUFSIZ];
	struct epoll_event ev, events[EPOLL_EVENTS];
	struct seccomp_notif *req = (struct seccomp_notif *)req_b;
	struct arguments arguments;
	char path[PATH_MAX + 1];
	bool running = true;
	int pidfd, notifier;
	struct gluten g;
	int fd, epollfd;
	int notifierfd;
	int nevents, i;

	arguments.pid = -1;
	parse(argc, argv, &arguments);
	fd = open(arguments.input_file, O_CLOEXEC | O_RDONLY);
	if (read(fd, &g, sizeof(g)) != sizeof(g))
		die("Failed to read gluten file");
	close(fd);

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
	} else if (arguments.socket != NULL) {
		unlink(arguments.socket);
		if ((fd = create_socket(arguments.socket)) < 0)
			die("  creating the socket");
		if ((notifier = recvfd(fd)) < 0)
			die("  failed recieving the notifier fd");
	}
	sleep(1);

	if ((epollfd = epoll_create1(0)) < 0)
		die("  epoll_create");
	ev.events = EPOLLIN;
	ev.data.fd = notifier;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, notifier, &ev) == -1)
		die("  epoll_ctl: notifier");

	while (running) {
		nevents = epoll_wait(epollfd, events, EPOLL_EVENTS, -1);
		if (nevents < 0)
			die("  waiting for seccomp events");
		memset(req, 0, sizeof(*req));
		if (ioctl(notifier, SECCOMP_IOCTL_NOTIF_RECV, req) < 0)
			die("  recieving seccomp notification");
		for (i = 0; i < nevents; ++i) {
			if (events[i].events & EPOLLHUP) {
				/* The notifier fd was closed by the target */
				running = false;
			} else if (notifier == events[i].data.fd) {
				if (eval(&g, req, notifier) == -1 )
					err("  an error occured during the evaluation");
			}
		}
	}
	if (strcmp(arguments.socket, "") > 0)
		unlink(arguments.socket);
}

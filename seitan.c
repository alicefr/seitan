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
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <argp.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define EPOLL_EVENTS 8

static char doc[] = "Usage: seitan: setain -pid <pid> -i <input file> ";

/* Seitan options */
static struct argp_option options[] = {
	{ "input", 'i', "FILE", 0, "Action input file", 0 },
	{ "pid", 'p', "pid", 0, "Pid of process to monitor", 0 },
	{ 0 }
};

struct arguments {
	char *input_file;
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
	case ARGP_KEY_END:
		if (arguments->input_file == NULL)
			argp_error(state, "missing input file");
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

static void unblock_eater(int pidfd){
	if (pidfd_send_signal(pidfd, SIGCONT, NULL, 0) == -1) {
		perror("pidfd_send_signal");
		exit(EXIT_FAILURE);
	}
}

static int find_fd_seccomp_notifier(int pid)
{
	char path[PATH_MAX + 1];
	char entry[2*PATH_MAX + 1];
	char buf[PATH_MAX + 1];
	struct dirent *dp;
	ssize_t nbytes;
	struct stat sb;
	DIR *dirp;

	snprintf(path, sizeof(path), "/proc/%i/fd", pid);
	if ((dirp = opendir(path)) == NULL) {
		fprintf(stderr,"failed reading fds from proc \n");
		return -1;
	}
	while ((dp = readdir (dirp)) != NULL) {
		snprintf(entry, sizeof(entry), "%s/%s", path, dp->d_name);
		if (lstat(entry, &sb) == -1) {
			perror("lstat");
		}
		/* Skip the entry if it isn't a symbolic link */
		if (!S_ISLNK(sb.st_mode))
			continue;

		nbytes = readlink(entry, buf, PATH_MAX);
		if (nbytes == -1) {
			perror("readlink");
		}
		if (nbytes == PATH_MAX) {
			perror("buffer overflow");
			continue;
		}
		/*
		 * From man proc: For  file  descriptors  that  have no
		 * corresponding inode (e.g., file descriptors produced by
		 * bpf(2)..), the  entry  will be a symbolic link with contents
		 * of the form:
		 * 	anon_inode:<file-type>
		 */
		if (strcmp(buf, "anon_inode:seccomp notify") == 0)
			return atoi(dp->d_name);
	}
	return -1;
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
	struct epoll_event ev, events[EPOLL_EVENTS];
	struct seccomp_notif_resp *resp = (struct seccomp_notif_resp *)resp_b;
	struct seccomp_notif *req = (struct seccomp_notif *)req_b;
	struct arguments arguments;
	bool running = true;
	int fd, epollfd;
	int notifierfd;
	int nevents,i;

	arguments.pid = -1;
	argp_parse(&argp, argc, argv, 0, 0, &arguments);
	fd = open(arguments.input_file, O_CLOEXEC | O_RDONLY);
	read(fd, t, sizeof(t));
	close(fd);

	if (arguments.pid < 0)
		while ((ret = event(s)) == -EAGAIN);
	else
		ret = arguments.pid;

	if (ret < 0)
		exit(EXIT_FAILURE);

	if ((pidfd = syscall(SYS_pidfd_open, ret, 0)) < 0) {
		perror("pidfd_open");
		exit(EXIT_FAILURE);
	}
	sleep(1);

	if ((notifierfd = find_fd_seccomp_notifier(ret)) < 0){
		fprintf(stderr, "failed getting fd of the notifier\n");
		exit(EXIT_FAILURE);
	}
	printf("fd notifier: %d \n", notifierfd);
	if ((notifier = syscall(SYS_pidfd_getfd, pidfd, notifierfd, 0)) < 0) {
		perror("pidfd_getfd");
		exit(EXIT_FAILURE);
	}

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
	/* Unblock seitan-loader */
	unblock_eater(pidfd);

	while(running) {
		nevents = epoll_wait(epollfd, events, EPOLL_EVENTS, -1);
		if (nevents < 0 ) {
			perror("epoll_wait");
			exit(EXIT_FAILURE);
		}
		/* TODO: Open syscall transformation table blob, actually handle
		 * syscalls actions as parsed
		 */
		memset(req, 0, sizeof(*req));
		for (i = 0; i < nevents; ++i) {
			if (events[i].events & EPOLLHUP) {
				/* The notifier fd was closed by the target */
				running = false;
			} else if (notifier == events[i].data.fd) {
				if (!handle(req, events[i].data.fd))
					continue;

				resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
				resp->id = req->id;
				resp->error = 0;
				resp->val = 0;

				ioctl(notifier, SECCOMP_IOCTL_NOTIF_SEND, resp);
			}
		}
	}
}

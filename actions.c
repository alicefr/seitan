#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <errno.h>

#include "gluten.h"
#include "actions.h"

static int send_target(const struct seccomp_notif_resp *resp, int notifyfd)
{
	if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
		if (errno != EINPROGRESS && errno != ENOENT) {
			perror("sending the response");
			return -1;
		}
	}
	return 0;

}

static int send_inject_target(const struct seccomp_notif_addfd *resp, int notifyfd)
{
	if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ADDFD, &resp) < 0) {
		if (errno != EINPROGRESS && errno != ENOENT) {
			perror("sending the response");
			return -1;
		}
	}
	return 0;

}

static void proc_ns_name(unsigned i, char *ns)
{
	char cgroup[PATH_MAX];

	switch(i){
		case NS_CGROUP:
			snprintf(ns, PATH_MAX + 1, "cgroup");
			break;
		case NS_IPC:
			snprintf(ns, PATH_MAX + 1,"ipc");
			break;
		case NS_NET:
			snprintf(ns, PATH_MAX + 1,"net");
			break;
		case NS_MOUNT:
			snprintf(ns, PATH_MAX + 1, "mnt");
			break;
		case NS_PID:
			snprintf(ns, PATH_MAX + 1,"pid");
			break;
		case NS_USER:
			snprintf(ns, PATH_MAX + 1, "user");
			break;
		case NS_UTS:
			snprintf(ns, PATH_MAX + 1,"uts");
			break;
		case NS_TIME:
			snprintf(ns, PATH_MAX + 1,"time");
			break;
		default:
			fprintf(stderr, "unrecognized namespace index %d\n", i);
	}
}

static int set_namespaces(const struct act_call *a, int tpid)
{
	char path[PATH_MAX +1];
	char ns_name[PATH_MAX + 1];
	struct ns_spec ns;
	int fd;
	ssize_t nbytes;
	unsigned int i;

	for (i = 0, ns = (a->context).ns[i] ; i < sizeof(enum ns_type); i++,
			ns = (a->context).ns[i]) {
		proc_ns_name(i, ns_name);
		switch(ns.type) {
			case NS_NONE:
				continue;
			case NS_SPEC_TARGET:
				snprintf(path, sizeof(path), "/proc/%d/ns/%s", tpid, ns_name);
				break;
			case NS_SPEC_PID:
				snprintf(path, sizeof(path), "/proc/%d/ns/%s", ns.pid, ns_name);
				break;
			case NS_SPEC_PATH:
				snprintf(path, sizeof(path), "%s", ns.path);
				break;
		}
		if (nbytes == PATH_MAX) {
			fprintf(stderr, "buffer overflow\n");
			return -1;
		}
		if ((fd = open(path, O_CLOEXEC)) < 0) {
			fprintf(stderr, "open for file %s: %s", path, strerror(errno));
			return -1;
		}

		if (setns(fd, 0) != 0){
			perror("setns");
			return -1;
		}
	}
	return 0;
}

static int execute_syscall(void *args)
{
	struct arg_clone *a = (struct arg_clone *)args;
	const struct act_call *c = a->args;

	if (set_namespaces(a->args, a->pid) < 0) {
		exit(EXIT_FAILURE);
	}
	/* execute syscall */
	a->ret = syscall(c->nr, c->args[0], c->args[1],
			c->args[2], c->args[3],
			c->args[4], c->args[5]);
	a->err = errno;
	if (a->ret < 0) {
		perror("syscall");
		exit(EXIT_FAILURE);
	}
	exit(0);
}

int do_call(struct arg_clone *c)
{
	char stack[STACK_SIZE];
	pid_t child;

	c->ret = -1;
	c->err = 0;

	/* Create a process that will be moved to the namespace */
	child = clone(execute_syscall, stack + sizeof(stack),
			 CLONE_FILES | CLONE_VM | SIGCHLD,
			 (void *)c);
	if (child == -1) {
		perror("clone");
		return -1;
	}
	wait(NULL);
	return 0;
}

int do_actions(struct action actions[], unsigned int n_actions, int pid,
		int notifyfd, uint64_t id)
{
	struct seccomp_notif_resp resp;
	struct arg_clone c;
	unsigned int i;

	for(i = 0;i < n_actions; i++) {
		memset(&resp, 0, sizeof(resp));
		resp.id = id;
		switch(actions[i].type) {
			case A_CALL:
				c.args = &actions[i].call;
				c.pid = pid;
				if (do_call(&c) == -1) {
					resp.error = c.err;
					if (send_target(&resp, notifyfd) == -1)
						return -1;
				}
				break;
			case A_BLOCK:
				resp.error = actions[i].block.error;
				if (send_target(&resp, notifyfd) == -1)
					return -1;
				break;
			case A_RETURN:
				resp.val = actions[i].ret.value;
				if (send_target(&resp, notifyfd) == -1)
					return -1;
				break;
			default:
				fprintf(stderr, "unknow action %d \n", actions[i].type);
		}
	}
	return 0;
}

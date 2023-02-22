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
#include "operations.h"

static bool is_cookie_valid(int notifyFd, uint64_t id)
{
	return ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

static int send_target(const struct seccomp_notif_resp *resp, int notifyfd)
{
	if (!is_cookie_valid(notifyfd, resp->id)) {
		fprintf(stderr,
			"the response id isn't valid\ncheck if the targets has already terminated\n");
		return -1;
	}
	if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
		if (errno != EINPROGRESS) {
			perror("sending the response");
			return -1;
		}
	}
	return 0;
}

static int send_inject_target(const struct seccomp_notif_addfd *resp,
			      int notifyfd)
{
	if (!is_cookie_valid(notifyfd, resp->id)) {
		fprintf(stderr,
			"the response id isn't valid\ncheck if the targets has already terminated\n");
		return -1;
	}
	if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ADDFD, resp) < 0) {
		if (errno != EINPROGRESS) {
			perror("sending the response");
			return -1;
		}
	}
	return 0;
}

static void proc_ns_name(unsigned i, char *ns)
{
	switch (i) {
	case NS_CGROUP:
		snprintf(ns, PATH_MAX + 1, "cgroup");
		break;
	case NS_IPC:
		snprintf(ns, PATH_MAX + 1, "ipc");
		break;
	case NS_NET:
		snprintf(ns, PATH_MAX + 1, "net");
		break;
	case NS_MOUNT:
		snprintf(ns, PATH_MAX + 1, "mnt");
		break;
	case NS_PID:
		snprintf(ns, PATH_MAX + 1, "pid");
		break;
	case NS_USER:
		snprintf(ns, PATH_MAX + 1, "user");
		break;
	case NS_UTS:
		snprintf(ns, PATH_MAX + 1, "uts");
		break;
	case NS_TIME:
		snprintf(ns, PATH_MAX + 1, "time");
		break;
	default:
		fprintf(stderr, "unrecognized namespace index %d\n", i);
	}
}

static int set_namespaces(const struct op_call *a, int tpid)
{
	char path[PATH_MAX + 1];
	char ns_name[PATH_MAX / 2];
	struct ns_spec ns;
	int fd;
	unsigned int i;

	for (i = 0, ns = (a->context).ns[i]; i < sizeof(enum ns_type);
	     i++, ns = (a->context).ns[i]) {
		proc_ns_name(i, ns_name);
		switch (ns.type) {
		case NS_NONE:
			continue;
		case NS_SPEC_TARGET:
			snprintf(path, sizeof(path), "/proc/%d/ns/%s", tpid,
				 ns_name);
			break;
		case NS_SPEC_PID:
			snprintf(path, sizeof(path), "/proc/%d/ns/%s", ns.pid,
				 ns_name);
			break;
		case NS_SPEC_PATH:
			snprintf(path, sizeof(path), "%s", ns.path);
			break;
		}

		if ((fd = open(path, O_CLOEXEC)) < 0) {
			fprintf(stderr, "open for file %s: %s", path,
				strerror(errno));
			return -1;
		}

		if (setns(fd, 0) != 0) {
			perror("setns");
			return -1;
		}
	}
	return 0;
}

static int execute_syscall(void *args)
{
	struct arg_clone *a = (struct arg_clone *)args;
	const struct op_call *c = a->args;

	if (set_namespaces(a->args, a->pid) < 0) {
		exit(EXIT_FAILURE);
	}
	/* execute syscall */
	a->ret = syscall(c->nr, c->args[0], c->args[1], c->args[2], c->args[3],
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
		      CLONE_FILES | CLONE_VM | SIGCHLD, (void *)c);
	if (child == -1) {
		perror("clone");
		return -1;
	}
	wait(NULL);
	return 0;
}

static void set_inject_fields(uint64_t id, void *data, const struct op *a,
			      struct seccomp_notif_addfd *resp)
{
	const struct fd_type *new = &(a->inj).newfd;
	const struct fd_type *old = &(a->inj).oldfd;

	resp->flags = SECCOMP_ADDFD_FLAG_SETFD;
	resp->id = id;
	if (new->type == IMMEDIATE)
		resp->newfd = new->fd;
	else
		memcpy(&resp->srcfd, (uint16_t *)data + old->fd_off,
		       sizeof(resp->srcfd));
	if (old->type == IMMEDIATE)
		resp->srcfd = old->fd;
	else
		memcpy(&resp->srcfd, (uint16_t *)data + old->fd_off,
		       sizeof(resp->srcfd));
	resp->newfd_flags = 0;
}

int do_operations(void *data, struct op operations[], unsigned int n_operations,
	       int pid, int notifyfd, uint64_t id)
{
	struct seccomp_notif_addfd resp_fd;
	struct seccomp_notif_resp resp;
	struct arg_clone c;
	unsigned int i;

	for (i = 0; i < n_operations; i++) {
		switch (operations[i].type) {
		case OP_CALL:
			resp.id = id;
			resp.val = 0;
			resp.flags = 0;
			c.args = &operations[i].call;
			c.pid = pid;
			if (do_call(&c) == -1) {
				resp.error = -1;
				if (send_target(&resp, notifyfd) == -1)
					return -1;
			}
			if (c.err != 0) {
				resp.error = -1;
				if (send_target(&resp, notifyfd) == -1)
					return c.err;
			}
			/*
			 * The result of the call needs to be save as
			 * reference
			 */
			if (operations[i].call.has_ret) {
				memcpy((uint16_t *)data +
					       operations[i].call.ret_off,
				       &c.ret, sizeof(c.ret));
			}
			break;
		case OP_BLOCK:
			resp.id = id;
			resp.val = 0;
			resp.flags = 0;
			resp.error = operations[i].block.error;
			if (send_target(&resp, notifyfd) == -1)
				return -1;
			break;
		case OP_RETURN:
			resp.id = id;
			resp.flags = 0;
			resp.error = 0;
			if (operations[i].ret.type == IMMEDIATE)
				resp.val = operations[i].ret.value;
			else
				memcpy(&resp.val,
				       (uint16_t *)data +
					       operations[i].ret.value_off,
				       sizeof(resp.val));

			if (send_target(&resp, notifyfd) == -1)
				return -1;
			break;

		case OP_CONT:
			resp.id = id;
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
			resp.error = 0;
			resp.val = 0;
			if (send_target(&resp, notifyfd) == -1)
				return -1;
			break;
		case OP_INJECT_A:
			set_inject_fields(id, data, &operations[i], &resp_fd);
			resp_fd.flags |= SECCOMP_ADDFD_FLAG_SEND;
			if (send_inject_target(&resp_fd, notifyfd) == -1)
				return -1;
			break;
		case OP_INJECT:
			set_inject_fields(id, data, &operations[i], &resp_fd);
			if (send_inject_target(&resp_fd, notifyfd) == -1)
				return -1;
			break;
		default:
			fprintf(stderr, "unknow operation %d \n", operations[i].type);
		}
	}
	return 0;
}

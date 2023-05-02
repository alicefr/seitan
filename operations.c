/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * operations.c - Execution of bytecode operations
 *
 * Copyright 2023 Red Hat GmbH
 * Authors: Alice Frosi <afrosi@redhat.com>
 *	    Stefano Brivio <sbrivio@redhat.com>
 */

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
			snprintf(path, sizeof(path), "/proc/%d/ns/%s",
				 ns.id.pid, ns_name);
			break;
		case NS_SPEC_PATH:
			snprintf(path, sizeof(path), "%s", ns.id.path);
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

static int op_load(struct seccomp_notif *req, int notifier, struct gluten *g,
		   struct op_load *load)
{
	char path[PATH_MAX];
	int fd, ret = 0;

	snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
		perror("open mem");
		return -1;
	}

	/*
         * Avoid the TOCTOU and check if the read mappings are still valid
         */
	if (!is_cookie_valid(notifier, req->id)) {
		fprintf(stderr, "the seccomp request isn't valid anymore\n");
		ret = -1;
		goto out;
	}

	memcpy(gluten_write_ptr(g, load->dst),
	       gluten_ptr(&req->data, g, load->src),
	       load->size);

out:
	close(fd);
	return ret;
}

static int resolve_fd(void *data, struct op_resolvedfd *resfd, pid_t pid)
{
	char fdpath[PATH_MAX], buf[PATH_MAX];
	char *path = (char *)((uint16_t *)data + resfd->path_off);
	int *fd = (int *)((uint16_t *)data + resfd->fd_off);
	ssize_t nbytes;

	snprintf(fdpath, PATH_MAX, "/proc/%d/fd/%d", pid, *fd);
	if ((nbytes = readlink(fdpath, buf, resfd->path_size)) < 0) {
		fprintf(stderr, "error reading %s\n", fdpath);
		perror("readlink");
		return -1;
	}
	if (strcmp(path, buf) == 0)
		return 0;
	else
		return 1;
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

static void set_inject_fields(uint64_t id, struct gluten *g,
			      const struct op_inject *a,
			      struct seccomp_notif_addfd *resp)
{
	resp->flags = SECCOMP_ADDFD_FLAG_SETFD;
	resp->id = id;

	memcpy(&resp->newfd, gluten_ptr(NULL, g, a->new_fd),
	       sizeof(resp->newfd));
	memcpy(&resp->srcfd, gluten_ptr(NULL, g, a->new_fd),
	       sizeof(resp->srcfd));

	resp->newfd_flags = 0;
}

static int op_cmp(struct seccomp_notif *req, int notifier, struct gluten *g,
		  struct op_cmp *op)
{
	int res = memcmp(gluten_ptr(&req->data, g, op->x),
			 gluten_ptr(&req->data, g, op->y), op->size);
	enum op_cmp_type cmp = op->cmp;

	(void)notifier;

	if ((res == 0 && (cmp == CMP_EQ || cmp == CMP_LE || cmp == CMP_GE)) ||
	    (res < 0  && (cmp == CMP_LT || cmp == CMP_LE)) ||
	    (res > 0  && (cmp == CMP_GT || cmp == CMP_GE)))
		return op->jmp;

	return -1;
}

int do_operations(struct gluten *g, struct op *ops, struct seccomp_notif *req,
		  unsigned int n_ops, int notifyfd)
{
	struct seccomp_notif_addfd resp_fd;
	struct seccomp_notif_resp resp;
	struct arg_clone c;
	unsigned int i;
	struct op *op;
	int ret;

	for (i = 0, op = ops; i < n_ops; i++, op++) {
		switch (op->type) {
		case OP_CALL:
			resp.id = req->id;
			resp.val = 0;
			resp.flags = 0;
			c.args = &ops[i].op.call;
			c.pid = req->pid;
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
			if (ops[i].op.call.has_ret) {
				memcpy(gluten_write_ptr(g, op->op.call.ret),
				       &c.ret, sizeof(c.ret));
			}
			break;
		case OP_BLOCK:
			resp.id = req->id;
			resp.val = 0;
			resp.flags = 0;
			resp.error = ops[i].op.block.error;
			if (send_target(&resp, notifyfd) == -1)
				return -1;
			break;
		case OP_RETURN:
			resp.id = req->id;
			resp.flags = 0;
			resp.error = 0;

			memcpy(&resp.val,
			       gluten_ptr(&req->data, g, op->op.ret.val),
			       sizeof(resp.val));

			if (send_target(&resp, notifyfd) == -1)
				return -1;
			break;

		case OP_CONT:
			resp.id = req->id;
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
			resp.error = 0;
			resp.val = 0;
			if (send_target(&resp, notifyfd) == -1)
				return -1;
			break;
		case OP_INJECT_A:
			set_inject_fields(req->id, g, &ops[i].op.inject,
					  &resp_fd);
			resp_fd.flags |= SECCOMP_ADDFD_FLAG_SEND;
			if (send_inject_target(&resp_fd, notifyfd) == -1)
				return -1;
			break;
		case OP_INJECT:
			set_inject_fields(req->id, g, &ops[i].op.inject,
					  &resp_fd);
			if (send_inject_target(&resp_fd, notifyfd) == -1)
				return -1;
			break;
		case OP_LOAD:
			if (op_load(req, notifyfd, g, &op->op.load))
				return -1;

			break;
		case OP_END:
			return 0;
		case OP_CMP:
			ret = op_cmp(req, notifyfd, g, (struct op_cmp *)op);
			if (ret == -1)
				return -1;

			i = ret;
			break;
		case OP_RESOLVEDFD:
			ret = resolve_fd(g->data, &ops[i].op.resfd, req->pid);
			if (ret == -1)
				return -1;
			else if (ret == 1)
				i = ops[i].op.resfd.jmp;
			break;
		default:
			fprintf(stderr, "unknown operation %d \n", ops[i].type);
		}
	}
	return 0;
}

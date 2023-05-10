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

#include "common/gluten.h"
#include "operations.h"

static bool is_cookie_valid(int notifyFd, uint64_t id)
{
	return ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

static int send_target(const struct seccomp_notif_resp *resp, int notifier)
{
	if (!is_cookie_valid(notifier, resp->id)) {
		fprintf(stderr,
			"the response id isn't valid\ncheck if the targets has already terminated\n");
		exit(0);
	}
	if (ioctl(notifier, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
		if (errno != EINPROGRESS) {
			perror("sending the response");
			return -1;
		}
	}
	return 0;
}

static int send_inject_target(const struct seccomp_notif_addfd *resp,
			      int notifier)
{
	if (!is_cookie_valid(notifier, resp->id)) {
		fprintf(stderr,
			"the response id isn't valid\ncheck if the targets has already terminated\n");
		return -1;
	}
	if (ioctl(notifier, SECCOMP_IOCTL_NOTIF_ADDFD, resp) < 0) {
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

int op_load(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_load *load)
{
	const long unsigned int *src = gluten_ptr(&req->data, g, load->src);
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
	if (!check_gluten_limits(load->dst, load->size)) {
		ret = -1;
		goto out;
	}
	if (pread(fd, gluten_write_ptr(g, load->dst), load->size, *src) < 0) {
		perror("pread");
		return -1;
	}

out:
	close(fd);
	return ret;
}

int do_call(struct arg_clone *c)
{
	char stack[STACK_SIZE];
	pid_t child;

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

int op_call(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_call *op)
{
	struct seccomp_notif_resp resp;
	struct arg_clone c;

	resp.id = req->id;
	resp.val = 0;
	resp.flags = 0;
	resp.error = 0;
	c.args = op;
	c.pid = req->pid;
	c.err = 0;

	if (do_call(&c) == -1) {
		resp.error = -1;
		if (send_target(&resp, notifier) == -1)
			return -1;
	}
	if (c.err != 0) {
		resp.error = -1;
		if (send_target(&resp, notifier) == -1)
			return -1;
	}
	/*
	 * The result of the call needs to be save as
	 * reference
	 */
	if (op->has_ret)
		return gluten_write(g, op->ret, &c.ret, sizeof(c.ret));

	return 0;
}

int op_block(const struct seccomp_notif *req, int notifier, struct gluten *g,
	     struct op_block *op)
{
	struct seccomp_notif_resp resp;

	(void)g;
	resp.id = req->id;
	resp.val = 0;
	resp.flags = 0;
	resp.error = op->error;

	if (send_target(&resp, notifier) == -1)
		return -1;

	return 0;
}

int op_return(const struct seccomp_notif *req, int notifier, struct gluten *g,
	      struct op_return *op)
{
	struct seccomp_notif_resp resp;

	resp.id = req->id;
	resp.flags = 0;
	resp.error = 0;

	if (gluten_read(&req->data, g, &resp.val, op->val, sizeof(resp.val)) == -1)
		return -1;

	if (send_target(&resp, notifier) == -1)
		return -1;

	return 0;
}

int op_continue(const struct seccomp_notif *req, int notifier, struct gluten *g,
		void *op)
{
	struct seccomp_notif_resp resp;

	(void)g;
	(void)op;

	resp.id = req->id;
	resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	resp.error = 0;
	resp.val = 0;

	if (send_target(&resp, notifier) == -1)
		return -1;

	return 0;
}

static int do_inject(const struct seccomp_notif *req, int notifier,
		     struct gluten *g, struct op_inject *op, bool atomic)
{
	struct seccomp_notif_addfd resp;

	resp.flags = SECCOMP_ADDFD_FLAG_SETFD;
	resp.newfd_flags = 0;
	resp.id = req->id;

	if(gluten_read(NULL, g, &resp.newfd, op->new_fd, sizeof(resp.newfd)) == -1)
		return -1;
	if(gluten_read(NULL, g, &resp.srcfd, op->old_fd, sizeof(resp.srcfd)) == -1)
		return -1;

	if (atomic)
		resp.flags |= SECCOMP_ADDFD_FLAG_SEND;
	if (send_inject_target(&resp, notifier) == -1)
		return -1;

	return 0;
}

int op_inject(const struct seccomp_notif *req, int notifier, struct gluten *g,
	      struct op_inject *op)
{
	return do_inject(req, notifier, g, op, false);
}

int op_inject_a(const struct seccomp_notif *req, int notifier, struct gluten *g,
		struct op_inject *op)
{
	return do_inject(req, notifier, g, op, true);
}

int op_cmp(const struct seccomp_notif *req, int notifier, struct gluten *g,
	   struct op_cmp *op)
{
	int res = memcmp(gluten_ptr(&req->data, g, op->x),
			 gluten_ptr(&req->data, g, op->y), op->size);
	enum op_cmp_type cmp = op->cmp;

	(void)notifier;

	if ((res == 0 && (cmp == CMP_EQ || cmp == CMP_LE || cmp == CMP_GE)) ||
	    (res < 0 && (cmp == CMP_LT || cmp == CMP_LE)) ||
	    (res > 0 && (cmp == CMP_GT || cmp == CMP_GE)) ||
	    (res != 0 && (cmp == CMP_NE)))
		return op->jmp;

	return 0;
}

int op_resolve_fd(const struct seccomp_notif *req, int notifier,
		  struct gluten *g, struct op_resolvedfd *op)
{
	char fdpath[PATH_MAX], buf[PATH_MAX], path[PATH_MAX];
	ssize_t nbytes;
	int fd;

	(void)notifier;


	if(gluten_read(NULL, g, &path, op->path, sizeof(op->path_size)) == -1)
		return -1;
	if(gluten_read(NULL, g, &fd, op->fd, sizeof(fd)) == -1)
		return -1;

	snprintf(fdpath, PATH_MAX, "/proc/%d/fd/%d", req->pid, fd);
	if ((nbytes = readlink(fdpath, buf, op->path_size)) < 0) {
		fprintf(stderr, "error reading %s\n", fdpath);
		perror("readlink");
		return -1;
	}
	if (strcmp(path, buf) == 0)
		return op->jmp;

	return 0;
}

int eval(struct gluten *g, struct op *ops, const struct seccomp_notif *req,
	  int notifier)
{
	struct op *op = ops;

	while (op->type != OP_END) {
		switch (op->type) {
			HANDLE_OP(OP_CALL, op_call, call);
			HANDLE_OP(OP_BLOCK, op_block, block);
			HANDLE_OP(OP_RETURN, op_return, ret);
			HANDLE_OP(OP_CONT, op_continue, cont);
			HANDLE_OP(OP_INJECT_A, op_inject_a, inject);
			HANDLE_OP(OP_INJECT, op_inject, inject);
			HANDLE_OP(OP_LOAD, op_load, load);
			HANDLE_OP(OP_CMP, op_cmp, cmp);
			HANDLE_OP(OP_RESOLVEDFD, op_resolve_fd, resfd);
		default:
			fprintf(stderr, "unknown operation %d \n", op->type);
		}
	}
	return 0;
}

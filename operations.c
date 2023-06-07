// SPDX-License-Identifier: GPL-2.0-or-later

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
#include "common/util.h"
#include "operations.h"

static bool is_cookie_valid(int notifyFd, uint64_t id)
{
	return ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

static int send_target(const struct seccomp_notif_resp *resp, int notifier)
{
	if (!is_cookie_valid(notifier, resp->id))
		ret_err(-1, "  the response id isn't valid");
	if (ioctl(notifier, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0)
		if (errno != EINPROGRESS)
			ret_err(-1, "  sending the response");
	return 0;
}

static int send_inject_target(const struct seccomp_notif_addfd *resp,
			      int notifier)
{
	if (!is_cookie_valid(notifier, resp->id))
		ret_err(-1, "  the response id isn't valid");
	if (ioctl(notifier, SECCOMP_IOCTL_NOTIF_ADDFD, resp) < 0)
		if (errno != EINPROGRESS)
			ret_err(-1, "  sending the response");
	return 0;
}

static struct gluten_offset *get_syscall_ret(struct syscall_desc *s)
{
	if (s == NULL)
		return NULL;
	if (s->has_ret == 0)
		return NULL;
	if (s->arg_count == 0)
		return &s->args[0];
	return &s->args[s->arg_count];
}

static int write_syscall_ret(struct gluten *g, struct syscall_desc *s,
			     const struct arg_clone *c)
{
	struct gluten_offset *p = get_syscall_ret(s);

	if (p != NULL) {
		debug("  op_call: write return value=%ld",c->ret);
		if (gluten_write(g, *p, &c->ret, sizeof(c->ret)) == -1)
			ret_err(-1, "  failed writing return value at %d", p->offset);
	}

	return 0;
}

static int prepare_arg_clone(const struct seccomp_notif *req, struct gluten *g,
			     struct syscall_desc *s, struct ns_spec *ctx,
			     struct arg_clone *c)
{
	unsigned int i, n = 0;
	long arg;

	c->err = 0;
	c->ret = -1;
	c->nr = s->nr;

	for (i = 0; i < s->arg_count; i++) {
		/* If arg is a pointer then need to calculate the absolute
		 * address and the value of arg is the relative offset of the actual
		 * value.
		*/
		if (GET_BIT(s->arg_deref, i) == 1) {
			c->args[i] = gluten_ptr(NULL, g, s->args[i]);
			debug("  read pointer arg%d at offset %d", i, s->args[i].offset);
		} else {
			if (gluten_read(NULL, g, &arg, s->args[i],
					sizeof(arg)) == -1)
				ret_err(-1, "  failed reading arg %d", i);
			debug("  read arg%d at offset %d v=%ld", i,
			      s->args[i].offset, arg);
			c->args[i] = (void *)arg;
		}
	}

	/* TODO: add proper check when there is no context */
	if (ctx == NULL)
		return 0;

	for (; ctx->spec != NS_SPEC_NONE; ctx++) {
		enum ns_spec_type spec = ctx->spec;
		enum ns_type ns = ctx->ns;

		switch (spec) {
		case NS_SPEC_NONE:
			break;
		case NS_SPEC_CALLER:
			snprintf(c->ns_path[n++], PATH_MAX, "/proc/%d/ns/%s",
				 req->pid, ns_type_name[ns]);
			break;
		case NS_SPEC_PID:
			snprintf(c->ns_path[n++], PATH_MAX, "/proc/%d/ns/%s",
				 ctx->target.pid, ns_type_name[ns]);
			break;
		case NS_SPEC_PATH:
			strncpy(c->ns_path[n++], ctx->target.path,
				PATH_MAX);
			break;
		}
	}

	*c->ns_path[n] = 0;

	return 0;
}

static int set_namespaces(struct arg_clone *c)
{
	char *path;
	int fd;

	for (path = c->ns_path[0]; *path; path++) {
		if ((fd = open(path, O_CLOEXEC)) < 0)
			ret_err(-1, "open for file %s", path);

		if (setns(fd, 0) != 0)
			ret_err(-1, "setns");
	}
	return 0;
}

static int execute_syscall(void *args)
{
	struct arg_clone *c = (struct arg_clone *)args;

	if (set_namespaces(c) < 0) {
		exit(EXIT_FAILURE);
	}
	/* execute syscall */
	c->ret = syscall(c->nr, c->args[0], c->args[1], c->args[2], c->args[3],
			 c->args[4], c->args[5]);
	c->err = errno;
	if (c->ret < 0) {
		perror("  syscall");
		exit(EXIT_FAILURE);
	}
	exit(0);
}

int do_call(struct arg_clone *c)
{
	char stack[STACK_SIZE];
	pid_t child;

	/* Create a process that will be moved to the namespace */
	child = clone(execute_syscall, stack + sizeof(stack),
		      CLONE_FILES | CLONE_VM | CLONE_VFORK | SIGCHLD, (void *)c);
	if (child == -1)
		ret_err(-1, "clone");
	return 0;
}

int op_call(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_call *op)
{
	struct seccomp_notif_resp resp;
	struct arg_clone c = { 0 };
	struct syscall_desc *s;
	struct ns_spec *ctx;

	resp.id = req->id;
	resp.val = 0;
	resp.flags = 0;
	resp.error = 0;

	s = (struct syscall_desc *)gluten_ptr(NULL, g, op->desc);
	ctx = (struct ns_spec *)gluten_ptr(NULL, g, s->context);

	if (prepare_arg_clone(req, g, s, ctx, &c) == -1)
		return -1;

	debug("  op_call: execute syscall nr=%ld", c.nr);
	if (do_call(&c) == -1) {
		resp.error = -1;
		if (send_target(&resp, notifier) == -1)
			return -1;
	}
	if (c.err != 0) {
		err("  failed executing call: %s", strerror(c.err));
		resp.error = -1;
		if (send_target(&resp, notifier) == -1)
			return -1;
	}

	return write_syscall_ret(g, s, &c);
}

int op_load(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_load *load)
{
	const long unsigned int *src = gluten_ptr(&req->data, g, load->src);
	void *dst = gluten_write_ptr(g, load->dst);
	char path[PATH_MAX];
	int fd, ret = 0;

	debug("  op_load: argument (%s %d) in (%s %d) size=%d",
	      gluten_offset_name[load->src.type], load->src.offset,
	      gluten_offset_name[load->dst.type], load->dst.offset, load->size);

	if(dst == NULL)
		ret_err(-1, "  op_load: empty destination");

	snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0)
		ret_err(-1, "error opening mem for %d", req->pid);
	/*
         * Avoid the TOCTOU and check if the read mappings are still valid
         */
	if (!is_cookie_valid(notifier, req->id)) {
		err("the seccomp request isn't valid anymore");
		ret = -1;
		goto out;
	}
	if (!check_gluten_limits(load->dst, load->size)) {
		ret = -1;
		goto out;
	}
	if (pread(fd, dst, load->size, *src) < 0) {
		err("pread");
		ret = -1;
		goto out;
	}

out:
	close(fd);
	return ret;
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

	if (gluten_read(&req->data, g, &resp.val, op->val, sizeof(resp.val)) ==
	    -1)
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

int op_fd(const struct seccomp_notif *req, int notifier,
	  struct gluten *g, struct op_fd *op)
{
	const struct fd_desc *desc = gluten_ptr(&req->data, g, op->desc);
	struct seccomp_notif_addfd resp;
	const void *fd;

	if (!desc)
		return -1;

	resp.flags = SECCOMP_ADDFD_FLAG_SETFD;
	resp.flags |= desc->do_return ? SECCOMP_ADDFD_FLAG_SEND : 0;
	resp.newfd_flags = desc->cloexec ? O_CLOEXEC : 0;
	resp.id = req->id;

	if (!(fd = gluten_ptr(&req->data, g, desc->srcfd)))
		return -1;
	resp.srcfd = *(uint32_t *)fd;

	if (desc->setfd) {
		if (!(fd = gluten_ptr(&req->data, g, desc->newfd)))
			return -1;
		resp.newfd = *(uint32_t *)fd;
	} else {
		resp.newfd = 0;
	}

	if (send_inject_target(&resp, notifier) == -1)
		return -1;

	return 0;
}

int op_mask(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_mask *op)
{
	const struct mask_desc *desc = gluten_ptr(&req->data, g, op->desc);
	const unsigned char *src, *mask;
	unsigned char *dst;
	unsigned i;

	(void)notifier;

	if (!desc)
		return -1;

	dst  = gluten_write_ptr(      g, desc->dst);
	src  = gluten_ptr(&req->data, g, desc->src);
	mask = gluten_ptr(&req->data, g, desc->mask);

/*
	if (!dst || !src || !mask ||
	    !check_gluten_limits(desc->dst,  desc->size) ||
	    !check_gluten_limits(desc->src,  desc->size) ||
	    !check_gluten_limits(desc->mask, desc->size))
		return -1;
*/
	debug("  op_mask: dst=(%s %d) src=(%s %d) mask=(%s %d) size=%d",
	      gluten_offset_name[desc->dst.type],  desc->dst.offset,
	      gluten_offset_name[desc->src.type],  desc->src.offset,
	      gluten_offset_name[desc->mask.type], desc->mask.offset,
	      desc->size);

	for (i = 0; i < desc->size; i++)
		dst[i] = src[i] & mask[i];

	return 0;
}

int op_cmp(const struct seccomp_notif *req, int notifier, struct gluten *g,
	   struct op_cmp *op)
{
	const struct cmp_desc *desc = gluten_ptr(&req->data, g, op->desc);
	enum op_cmp_type cmp;
	const void *px, *py;
	int res;

	(void)notifier;

	if (!desc)
		return -1;

	px  = gluten_ptr(&req->data, g, desc->x);
	py  = gluten_ptr(&req->data, g, desc->y);
	cmp = desc->cmp;

	if (!px || !py ||
	    !check_gluten_limits(desc->x, desc->size) ||
	    !check_gluten_limits(desc->y, desc->size))
		return -1;

	debug("  op_cmp: operands x=(%s %d) y=(%s %d) size=%d",
	      gluten_offset_name[desc->x.type], desc->x.offset,
	      gluten_offset_name[desc->y.type], desc->y.offset, desc->size);

	res = memcmp(px, py, desc->size);

	if ((res == 0 && (cmp == CMP_EQ || cmp == CMP_LE   || cmp == CMP_GE)) ||
	    (res < 0  && (cmp == CMP_LT || cmp == CMP_LE)) ||
	    (res > 0  && (cmp == CMP_GT || cmp == CMP_GE)) ||
	    (res != 0 && (cmp == CMP_NE))) {
		debug("  op_cmp: successful comparison, jump to %d",
		      desc->jmp.offset);
		return desc->jmp.offset;
	}
	debug("  op_cmp: comparison is false");

	return 0;
}

int op_resolve_fd(const struct seccomp_notif *req, int notifier,
		  struct gluten *g, struct op_resolvefd *op)
{
	const struct resolvefd_desc *desc = gluten_ptr(&req->data, g, op->desc);
	char fdpath[PATH_MAX], buf[PATH_MAX];
	ssize_t nbytes;
	int fd;

	(void)notifier;

	debug("  op_resolvefd: fd=(%s %d) path=(%s %d) path_max=%d",
	      gluten_offset_name[desc->fd.type], desc->fd.offset,
	      gluten_offset_name[desc->path.type], desc->path.offset,
	      desc->path_max);

	if (gluten_read(&req->data, g, &fd, desc->fd, sizeof(fd)) == -1)
		return -1;

	snprintf(fdpath, PATH_MAX, "/proc/%d/fd/%d", req->pid, fd);
	if ((nbytes = readlink(fdpath, buf, desc->path_max)) < 0)
		ret_err(-1, "error reading %s", buf);

	debug("  op_resolvefd: fd %d -> path: %s", fd, buf);
	gluten_write(g, desc->path, &buf, desc->path_max);

	return 0;
}

int op_nr(const struct seccomp_notif *req, int notifier, struct gluten *g,
	  struct op_nr *op)
{
	long nr;

	(void)notifier;

	if (gluten_read(NULL, g, &nr, op->nr, sizeof(nr)) == -1)
		return -1;
	debug("  op_nr: checking syscall=%ld", nr);
	if (nr == req->data.nr)
		return 0;

	debug("  op_nr: jmp to instr %d", op->no_match.offset);
	return op->no_match.offset;
}

int op_copy(const struct seccomp_notif *req, int notifier, struct gluten *g,
	    struct op_copy *op)
{
	(void)notifier;

	return gluten_write(g, op->dst, gluten_ptr(&req->data, g, op->src),
			    op->size);
}

int eval(struct gluten *g, const struct seccomp_notif *req,
	 int notifier)
{
	struct op *op = (struct op *)g->inst;

	while (op->type != OP_END) {
		debug("at instruction %i", op - (struct op *)g->inst);
		switch (op->type) {
			HANDLE_OP(OP_CALL, op_call, call, g);
			HANDLE_OP(OP_BLOCK, op_block, block, g);
			HANDLE_OP(OP_RETURN, op_return, ret, g);
			HANDLE_OP(OP_CONT, op_continue, NO_FIELD, g);
			HANDLE_OP(OP_FD, op_fd, fd, g);
			HANDLE_OP(OP_LOAD, op_load, load, g);
			HANDLE_OP(OP_MASK, op_mask, mask, g);
			HANDLE_OP(OP_CMP, op_cmp, cmp, g);
			HANDLE_OP(OP_RESOLVEDFD, op_resolve_fd, resfd, g);
			HANDLE_OP(OP_NR, op_nr, nr, g);
			HANDLE_OP(OP_COPY, op_copy, copy, g);
		default:
			ret_err(-1, "unknown operation %d", op->type);
		}
	}
	return 0;
}

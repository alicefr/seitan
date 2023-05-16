/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include <check.h>

#include "common/gluten.h"
#include "operations.h"
#include "testutil.h"

struct args_write_file {
	char *file;
	char *t;
	ssize_t size;
};

static long nr;

static void write_arg(struct op_call *call, int i, long v)
{
	ck_write_gluten(gluten, call->args[i], v);
}

static void write_file(char *file, char *t, ssize_t size)
{
	int fd;

	fd = open(file, O_CREAT | O_RDWR, S_IWUSR | S_IRUSR);
	ck_assert_int_ge(fd, -1);
	write(fd, t, size);
	close(fd);
}

static int write_file_get_fd(char *file, char *t, ssize_t size)
{
	int fd;

	write_file(file, t, size);
	fd = open(file, O_RDONLY, S_IWUSR);
	unlink(file);
	return fd;
}

static int write_file_clone(void *a)
{
	struct args_write_file *args = (struct args_write_file *)a;
	write_file(args->file, args->t, args->size);
	install_single_syscall(SYS_getpid);
	getpid();
	return 0;
}

static void set_ns_to_none(struct op_call *call)
{
	for (unsigned int i = 0; i < NS_NUM; i++)
		call->context.ns[i].type = NS_NONE;
}

static void setup_ns(struct args_write_file *args)
{
        at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->nr = __NR_getpid;
	at->target = write_file_clone;
	at->tclone = (void *)args;
	at->ns[NS_MOUNT] = true;
	setup();
}

START_TEST(test_with_read)
{
	char test_file[] = "/tmp/test.txt";
	char t[PATH_MAX] = "Hello Test";
	struct op_call call = {
		{ OFFSET_RO_DATA, 0 },
		{
			{ OFFSET_DATA, 0 },
			{ OFFSET_DATA, sizeof(long) },
			{ OFFSET_DATA, sizeof(long) * 2 },
		},
		.has_ret = true,
		.ret = { OFFSET_DATA, sizeof(long) * 3 },
	};
	char buf[PATH_MAX];
	long count, ret;
	int fd;

	fd = write_file_get_fd(test_file, t, sizeof(t));
	count = sizeof(buf);
	for (unsigned int i = 0; i < NS_NUM; i++)
		call.context.ns[i].type = NS_NONE;

	nr = SYS_read;
	ck_write_gluten(gluten, call.nr, nr);
	write_arg(&call, 0, (long)fd);
	write_arg(&call, 1, (long)&buf);
	write_arg(&call, 2, (long)count);
	nr = SYS_read;

	ck_assert_int_eq(op_call(&req, notifyfd, &gluten, &call), 0);

	ck_read_gluten(gluten, call.ret, ret);
	ck_assert_msg(ret == count, "expect ret %ld to be %ld", ret, count);
	ck_assert_str_eq(t, buf);
}
END_TEST

START_TEST(test_with_getppid)
{
	struct op_call call = {
		.nr = { OFFSET_RO_DATA, 0 },
		.has_ret = true,
		.ret = { OFFSET_DATA, 0 },
	};
	long pid = (long)getpid();
	int ret = -1;

	for (unsigned int i = 0; i < NS_NUM; i++)
		call.context.ns[i].type = NS_NONE;

	nr = SYS_getppid;
	ck_write_gluten(gluten, call.nr, nr);

	ck_assert_int_eq(op_call(&req, notifyfd, &gluten, &call), 0);

	ck_read_gluten(gluten, call.ret, ret);
	ck_assert_msg(ret == pid, "expect ret %d to be equal to %ld", ret, pid);
}
END_TEST

START_TEST(test_with_open_read_ns)
{
	char test_file[] = "/tmp/test.txt";
	char t[PATH_MAX] = "Hello Test";
	struct args_write_file args = { test_file, t, sizeof(t) };
	struct op_call *call;
	struct op ops[] = {
		{ OP_CALL,
		  { .call = { { OFFSET_RO_DATA, 0 }, /* open */
			      {
				      { OFFSET_DATA, 0 },
				      { OFFSET_DATA, sizeof(long) },
				      { OFFSET_DATA, sizeof(long) * 2 },
			      },
			      .has_ret = true,
			      .ret = { OFFSET_DATA, sizeof(long) * 3 } } } },
		{ OP_CALL,
		  { .call = { { OFFSET_RO_DATA, sizeof(long) }, /* read */
			      {
				      { OFFSET_DATA, sizeof(long) * 3 }, /* ret of the previous call*/
				      { OFFSET_DATA, sizeof(long) * 5 },
				      { OFFSET_DATA, sizeof(long) * 6 },
			      },
			      .has_ret = true,
			      .ret = { OFFSET_DATA, sizeof(long) * 7 } } } },
		{ OP_END, OP_EMPTY },

	};
	int flags = O_RDWR;
	char buf[PATH_MAX];
	long count, rcount;

	setup_ns(&args);

	/* Copy and configure op_calls */
	set_ns_to_none(&ops[0].op.call);
	set_ns_to_none(&ops[1].op.call);

	nr = SYS_open;
	call = &ops[0].op.call;
	ck_write_gluten(gluten, call->nr, nr);
	write_arg(call, 0, (long)&test_file);
	write_arg(call, 1, (long)flags);
	call->context.ns[NS_MOUNT].type = NS_SPEC_TARGET;

	nr = SYS_read;
	call = &ops[1].op.call;
	count = sizeof(buf);
	ck_write_gluten(gluten, call->nr, nr);
	write_arg(call, 1, (long)&buf);
	write_arg(call, 2, (long)count);
	call->context.ns[NS_MOUNT].type = NS_SPEC_TARGET;

	write_instr(gluten, ops);

	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	ck_read_gluten(gluten, ops[1].op.call.ret, rcount);
	ck_assert_msg(rcount == count, "expect ret %ld to be %ld", rcount, count);
	ck_assert_str_eq(t, buf);
}
END_TEST


Suite *op_call_suite(void)
{
	Suite *s;
	TCase *tsimple, *tread, *treadns;
	int timeout = 30;

	s = suite_create("Perform ops call");

	tsimple = tcase_create("getppid");
	tcase_add_test(tsimple, test_with_getppid);
	suite_add_tcase(s, tsimple);

	tread = tcase_create("read");
	tcase_add_test(tread, test_with_read);
	suite_add_tcase(s, tread);

	treadns = tcase_create("read ns");

	tcase_add_checked_fixture(treadns, NULL, teardown);
	tcase_set_timeout(treadns, timeout);
	tcase_add_test(treadns, test_with_open_read_ns);
	suite_add_tcase(s, treadns);

	return s;
}

int main(void)
{
	int no_failed = 0;
	Suite *s;
	SRunner *runner;

	s = op_call_suite();
	runner = srunner_create(s);

	srunner_run_all(runner, CK_VERBOSE);
	no_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

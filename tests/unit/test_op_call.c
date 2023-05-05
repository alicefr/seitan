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

#include <check.h>

#include "common/gluten.h"
#include "operations.h"

struct args_write_file {
	char *file;
	char *t;
	ssize_t size;
};

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
	pause();
	return 0;
}

static pid_t create_func_ns(int (*fn)(void *), void *arg, struct ns_spec ns[])
{
	char stack[STACK_SIZE];
	pid_t child;
	int flags = SIGCHLD;
	unsigned int i;

	for (i = 0; i < sizeof(sizeof(enum ns_type)); i++) {
		if (ns[i].type == NS_NONE)
			continue;
		switch (i) {
		case NS_CGROUP:
			flags |= CLONE_NEWCGROUP;
			break;
		case NS_IPC:
			flags |= CLONE_NEWIPC;
			break;
		case NS_NET:
			flags |= CLONE_NEWNET;
			break;
		case NS_MOUNT:
			flags |= CLONE_NEWNS;
			break;
		case NS_PID:
			flags |= CLONE_NEWPID;
			break;
		case NS_USER:
			flags |= CLONE_NEWUSER;
			break;
		case NS_UTS:
			flags |= CLONE_NEWUTS;
			break;
		case NS_TIME:
			fprintf(stderr,
				"option NS_TIME not suppoted by clone\n");
			break;
		default:
			fprintf(stderr, "unrecognized option %d\n", i);
		}
	}
	child = clone(fn, stack + sizeof(stack), flags, arg);
	if (child == -1) {
		perror("clone");
		exit(EXIT_FAILURE);
	}
	return child;
}

START_TEST(test_with_open_read_ns)
{
	char test_file[] = "/tmp/test.txt";
	char t[PATH_MAX] = "Hello Test";
	struct args_write_file args = { test_file, t, sizeof(t) };
	struct op_call call;
	int flags = O_RDWR;
	struct arg_clone c;
	char buf[PATH_MAX];
	unsigned i;
	long count;
	pid_t pid;
	int ret;

	c.args = &call;
	count = sizeof(buf);
	for (i = 0; i < sizeof(enum ns_type); i++)
		call.context.ns[i].type = NS_NONE;
	call.context.ns[NS_MOUNT].type = NS_SPEC_PID;
	pid = create_func_ns(write_file_clone, (void *)&args, call.context.ns);
	call.context.ns[NS_MOUNT].id.pid = pid;
	call.nr = SYS_open;
	call.args[0] = (void *)&test_file;
	call.args[1] = (void *)(long)flags;
	ret = do_call(&c);
	ck_assert_int_eq(ret, 0);
	ck_assert_msg(c.ret >= 0, "expect ret %ld should be nonegative", c.ret);

	call.nr = SYS_read;
	call.args[0] = (void *)(long)c.ret;
	call.args[1] = (void *)&buf;
	call.args[2] = (void *)count;
	ret = do_call(&c);
	kill(pid, SIGCONT);

	ck_assert_int_eq(ret, 0);
	ck_assert_msg(c.ret == count, "expect ret %ld to be %ld", c.ret, count);
	ck_assert_str_eq(t, buf);
}
END_TEST

START_TEST(test_with_read)
{
	char test_file[] = "/tmp/test.txt";
	char t[PATH_MAX] = "Hello Test";
	struct op_call call;
	struct arg_clone c;
	char buf[PATH_MAX];
	unsigned i;
	long count;
	int fd, ret;

	c.args = &call;
	fd = write_file_get_fd(test_file, t, sizeof(t));
	count = sizeof(buf);
	for (i = 0; i < sizeof(enum ns_type); i++)
		call.context.ns[i].type = NS_NONE;
	call.nr = SYS_read;
	call.args[0] = (void *)(long)fd;
	call.args[1] = (void *)&buf;
	call.args[2] = (void *)count;
	ret = do_call(&c);

	ck_assert_int_eq(ret, 0);
	ck_assert_msg(c.ret == count, "expect ret %ld to be %ld", c.ret, count);
	ck_assert_str_eq(t, buf);
}
END_TEST

START_TEST(test_with_getppid)
{
	struct op_call call;
	struct arg_clone c;
	unsigned i;
	long pid = (long)getpid();
	int ret;

	for (i = 0; i < sizeof(enum ns_type); i++)
		call.context.ns[i].type = NS_NONE;
	call.nr = SYS_getppid;
	c.args = &call;
	ret = do_call(&c);
	ck_assert_int_eq(ret, 0);
	ck_assert_msg(c.ret == pid, "expect ret %ld to be equal to %ld", c.ret,
		      pid);
}
END_TEST

Suite *op_call_suite(void)
{
	Suite *s;
	TCase *tops;

	s = suite_create("Perform ops call");
	tops = tcase_create("op calls");

	tcase_add_test(tops, test_with_getppid);
	tcase_add_test(tops, test_with_read);
	tcase_add_test(tops, test_with_open_read_ns);

	suite_add_tcase(s, tops);

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

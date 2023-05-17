/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/socket.h>

#include <check.h>

#include "operations.h"
#include "common/common.h"
#include "testutil.h"

#define MAX_TEST_PATH 250

void setup_without_fd()
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getpid;
	at->install_filter = install_notification_filter;
	setup();
}
void setup_fd()
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = true;
	at->nr = __NR_getpid;
	at->install_filter = install_notification_filter;
	setup();
}

void setup_path()
{
	unlink(path);
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->open_path = true;
	at->nr = __NR_getpid;
	at->install_filter = install_notification_filter;
	setup();
}

void setup_target_connect()
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ck_assert_int_ge(fd, 0);
	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sun_path, "/tmp/test.sock");
	addr.sun_family = AF_UNIX;
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_connect;
	at->targs[0] = (void *)(long)fd;
	at->targs[1] = (void *)&addr;
	at->targs[2] = (void *)(long)(sizeof(char) * 108);
	at->install_filter = install_notification_filter;
	setup();
}

START_TEST(test_op_continue)
{
	ck_assert_msg(op_continue(&req, notifyfd, NULL, NULL) == 0,
		      strerror(errno));
	ck_assert_int_eq(at->err, 0);
}
END_TEST

START_TEST(test_op_block)
{
	struct op_block op = { -1 };

	ck_assert_msg(op_block(&req, notifyfd, NULL, &op) == 0,
		      strerror(errno));
	/*
	 * The tests use getpid that returns the error with ret and it is always
	 * successful
	 */
	check_target_result(op.error, 1, false);
}
END_TEST

static void test_op_return(enum gluten_offset_type type, uint16_t offset)
{
	struct op_return op = { { type, offset } };
	int64_t v = 2;

	ck_write_gluten(gluten, op.val, v);
	ck_assert_msg(op_return(&req, notifyfd, &gluten, &op) == 0,
		      strerror(errno));
	check_target_result(v, 0, false);
}

START_TEST(test_op_return_ro_data)
{
	test_op_return(OFFSET_RO_DATA, 4);
}
END_TEST

START_TEST(test_op_return_data)
{
	test_op_return(OFFSET_DATA, 4);
}
END_TEST

START_TEST(test_op_call)
{
	long nr = __NR_getppid;
	struct op operations[] = { { OP_CALL,
				     { .call = { .nr = { OFFSET_DATA, 0 } } } },
				   { OP_CONT, OP_EMPTY },
				   { OP_END, OP_EMPTY } };
	memcpy(&gluten.inst, &operations, sizeof(operations));
	ck_write_gluten(gluten, operations[0].op.call.nr, nr);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result(1, 0, true);
}
END_TEST

START_TEST(test_op_call_ret)
{
	long nr = __NR_getppid;
	long r;
	struct op operations[] = {
		{ OP_CALL,
		  { .call = { .nr = { OFFSET_DATA, 0 },
			      .ret = { OFFSET_DATA, sizeof(nr) },
			      .has_ret = true } } },
		{ OP_CONT, OP_EMPTY },
		{ OP_END, OP_EMPTY },
	};

	memcpy(&gluten.inst, &operations, sizeof(operations));
	ck_write_gluten(gluten, operations[0].op.call.nr, nr);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result(1, 0, true);
	ck_read_gluten(gluten, operations[0].op.call.ret, r);
	ck_assert(r == getpid());
}
END_TEST

static void test_inject(enum gluten_offset_type type, bool atomic)
{
	struct op_inject op = { { type, 0 }, { type, 4 } };
	int test_fd = 3;
	int fd_inj;

	fd_inj = create_test_fd();
	ck_assert_int_ge(fd_inj, 0);
	ck_write_gluten(gluten, op.old_fd, test_fd);
	ck_write_gluten(gluten, op.new_fd, fd_inj);

	if (atomic)
		op_inject(&req, notifyfd, &gluten, &op);
	else
		op_inject_a(&req, notifyfd, &gluten, &op);
	check_target_fd(pid, test_fd);
}

START_TEST(test_op_inject_a)
{
	test_inject(OFFSET_RO_DATA, true);
}
END_TEST

START_TEST(test_op_inject_a_ref)
{
	test_inject(OFFSET_DATA, true);
}
END_TEST

START_TEST(test_op_inject)
{
	test_inject(OFFSET_RO_DATA, false);
}
END_TEST

START_TEST(test_op_inject_ref)
{
	test_inject(OFFSET_DATA, false);
}
END_TEST

START_TEST(test_op_load)
{
	struct op operations[] = {
		{ OP_LOAD,
		  { .load = { { OFFSET_SECCOMP_DATA, 1 },
			      { OFFSET_DATA, 0 },
			      sizeof(struct sockaddr_un) } } },
		{ OP_RETURN,
		  { .ret = { { OFFSET_DATA, sizeof(struct sockaddr_un) } } } },
		{ OP_END, OP_EMPTY },
	};
	struct sockaddr_un addr;
	int v = 2;

	memcpy(&gluten.inst, &operations, sizeof(operations));
	ck_write_gluten(gluten, operations[1].op.ret.val, v);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result(v, 0, false);

	ck_read_gluten(gluten, operations[0].op.load.dst, addr);
	ck_assert_str_eq(addr.sun_path, "/tmp/test.sock");
	ck_assert(addr.sun_family == AF_UNIX);
}
END_TEST

static void test_op_cmp_int(int a, int b, enum op_cmp_type cmp)
{
	int jmp = 3;
	struct op operations[] = {
		{ OP_CMP,
		  { .cmp = { { OFFSET_DATA, 0 },
			     { OFFSET_DATA, 10 },
			     sizeof(int),
			     cmp,
			     { OFFSET_RO_DATA, 0 } } } },
		{ OP_BLOCK, { .block = { -1 } } },
		{ OP_END, OP_EMPTY },
		{ OP_CONT, OP_EMPTY },
		{ OP_END, OP_EMPTY },
	};

	memcpy(&gluten.inst, &operations, sizeof(operations));
	ck_write_gluten(gluten, operations[0].op.cmp.x, a);
	ck_write_gluten(gluten, operations[0].op.cmp.y, b);
	ck_write_gluten(gluten, operations[0].op.cmp.jmp, jmp);

	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result_nonegative();
}

START_TEST(test_op_cmp_int_eq)
{
	test_op_cmp_int(1, 1, CMP_EQ);
}
END_TEST

START_TEST(test_op_cmp_int_ne)
{
	test_op_cmp_int(1, 2, CMP_NE);
}
END_TEST

START_TEST(test_op_cmp_int_gt)
{
	test_op_cmp_int(2, 1, CMP_GT);
}
END_TEST

START_TEST(test_op_cmp_int_ge)
{
	test_op_cmp_int(1, 1, CMP_GE);
}
END_TEST

START_TEST(test_op_cmp_int_lt)
{
	test_op_cmp_int(1, 2, CMP_LT);
}
END_TEST

START_TEST(test_op_cmp_int_le)
{
	test_op_cmp_int(1, 1, CMP_LE);
}
END_TEST

START_TEST(test_op_cmp_string_eq)
{
	char s1[30] = "Hello Test!!";
	char s2[30] = "Hello Test!!";
	int jmp = 3;
	struct op operations[] = {
		{ OP_CMP,
		  { .cmp = { { OFFSET_DATA, 0 },
			     { OFFSET_DATA, 30 },
			     sizeof(s1),
			     CMP_EQ,
			     { OFFSET_RO_DATA, 0 } } } },
		{ OP_BLOCK, { .block = { -1 } } },
		{ OP_END, OP_EMPTY },
		{ OP_CONT, OP_EMPTY },
		{ OP_END, OP_EMPTY },
		{ 0 },
	};
	ck_write_gluten(gluten, operations[0].op.cmp.x, s1);
	ck_write_gluten(gluten, operations[0].op.cmp.y, s2);
	ck_write_gluten(gluten, operations[0].op.cmp.jmp, jmp);

	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result_nonegative();
}
END_TEST

START_TEST(test_op_cmp_string_false)
{
	char s1[30] = "Hello Test!!";
	char s2[30] = "Hello Tost!!";
	int jmp = 2;
	struct op operations[] = {
		{ OP_CMP,
		  { .cmp = { { OFFSET_DATA, 0 },
			     { OFFSET_DATA, 30 },
			     sizeof(s1),
			     CMP_EQ,
			     { OFFSET_RO_DATA, 0 } } } },
		{ OP_CONT, OP_EMPTY },
		{ OP_END, OP_EMPTY },
		{ OP_BLOCK, { .block = { -1 } } },
		{ OP_END, OP_EMPTY },
		{ 0 },
	};

	memcpy(&gluten.inst, &operations, sizeof(operations));
	ck_write_gluten(gluten, operations[0].op.cmp.x, s1);
	ck_write_gluten(gluten, operations[0].op.cmp.y, s2);
	ck_write_gluten(gluten, operations[0].op.cmp.jmp, jmp);

	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result_nonegative();
}
END_TEST

START_TEST(test_op_resolvedfd_eq)
{
	struct op operations[] = {
		{ OP_RESOLVEDFD,
		  { .resfd = { { OFFSET_DATA, 0 },
			       { OFFSET_DATA, 4 },
			       sizeof(path),
			       3 } } },
		{ OP_BLOCK, { .block = { -1 } } },
		{ OP_END, OP_EMPTY },
		{ OP_CONT, OP_EMPTY },
		{ OP_END, OP_EMPTY },
		{ 0 },
	};

	memcpy(&gluten.inst, &operations, sizeof(operations));
	ck_write_gluten(gluten, operations[0].op.resfd.fd, at->fd);
	ck_write_gluten(gluten, operations[0].op.resfd.path, path);

	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result(-1, 1, false);
}
END_TEST

START_TEST(test_op_resolvedfd_neq)
{
	char path2[] = "/tmp/seitan-test-wrong";
	struct op operations[] = {
		{ OP_RESOLVEDFD,
		  { .resfd = { { OFFSET_DATA, 0 },
			       { OFFSET_DATA, 4 },
			       sizeof(path),
			       3 } } },
		{ OP_BLOCK, { .block = { -1 } } },
		{ OP_END, OP_EMPTY },
		{ OP_CONT, OP_EMPTY },
		{ OP_END, OP_EMPTY },
	};

	memcpy(&gluten.inst, &operations, sizeof(operations));
	ck_write_gluten(gluten, operations[0].op.resfd.fd, at->fd);
	ck_write_gluten(gluten, operations[0].op.resfd.path, path2);

	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result(-1, 1, false);
}
END_TEST


START_TEST(test_op_nr)
{
	long nr = __NR_getpid;
	int jmp = 3;
	struct op operations[] = {
		{ OP_NR,
		  { .nr = { { OFFSET_RO_DATA, 0 },
			    { OFFSET_RO_DATA, sizeof(nr) } } } },
		{ OP_BLOCK, { .block = { -1 } } },
		{ OP_END, OP_EMPTY },
		{ OP_CONT, OP_EMPTY },
		{ OP_END, OP_EMPTY },
	};

	memcpy(&gluten.inst, &operations, sizeof(operations));
	ck_write_gluten(gluten, operations[0].op.nr.nr, nr);
	ck_write_gluten(gluten, operations[0].op.nr.no_match, jmp);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), 0);
	check_target_result_nonegative();
}

START_TEST(test_op_copy)
{
	int a[] = { 1, 2, 3, 4, 5, 6 };
	int b[ARRAY_SIZE(a)];
	struct op_copy op = { { OFFSET_DATA, 30 },
			      { OFFSET_DATA, 0 },
			      sizeof(a) };

	ck_write_gluten(gluten, op.src, a);
	ck_assert_msg(op_copy(&req, notifyfd, &gluten, &op) == 0,
		      strerror(errno));
	ck_read_gluten(gluten, op.dst, b);
	ck_assert_mem_eq(a, b, sizeof(a));
}
END_TEST

Suite *op_call_suite(void)
{
	Suite *s;
	int timeout = 30;
	TCase *cont, *block, *ret, *call, *resolvedfd;
	TCase *cmp, *cmpint;
	TCase *inject, *inject_a;
	TCase *load, *nr, *copy;

	s = suite_create("Perform operations");

	cont = tcase_create("op_continue");
	tcase_add_checked_fixture(cont, setup_without_fd, teardown);
	tcase_set_timeout(cont, timeout);
	tcase_add_test(cont, test_op_continue);
	suite_add_tcase(s, cont);

	block = tcase_create("op_block");
	tcase_add_checked_fixture(block, setup_without_fd, teardown);
	tcase_set_timeout(block, timeout);
	tcase_add_test(block, test_op_block);
	suite_add_tcase(s, block);

	ret = tcase_create("op_return");
	tcase_add_checked_fixture(ret, setup_without_fd, teardown);
	tcase_set_timeout(ret, timeout);
	tcase_add_test(ret, test_op_return_ro_data);
	tcase_add_test(ret, test_op_return_data);
	suite_add_tcase(s, ret);

	call = tcase_create("op_call");
	tcase_add_checked_fixture(call, setup_without_fd, teardown);
	tcase_set_timeout(call, timeout);
	tcase_add_test(call, test_op_call);
	tcase_add_test(call, test_op_call_ret);
	suite_add_tcase(s, call);

	inject = tcase_create("op_inject");
	tcase_add_checked_fixture(inject, setup_fd, teardown);
	tcase_set_timeout(inject, timeout);
	tcase_add_test(inject, test_op_inject);
	tcase_add_test(inject, test_op_inject_ref);
	suite_add_tcase(s, inject);

	inject_a = tcase_create("op_inject_a");
	tcase_add_checked_fixture(inject_a, setup_fd, teardown);
	tcase_set_timeout(inject_a, timeout);
	tcase_add_test(inject_a, test_op_inject_a);
	tcase_add_test(inject_a, test_op_inject_a_ref);
	suite_add_tcase(s, inject_a);

	load = tcase_create("op_load");
	tcase_add_checked_fixture(load, setup_target_connect, teardown);
	tcase_set_timeout(load, 120);
	tcase_add_test(load, test_op_load);
	suite_add_tcase(s, load);

	cmp = tcase_create("op_cmp");
	tcase_add_checked_fixture(cmp, setup_without_fd, teardown);
	tcase_set_timeout(cmp, timeout);
	tcase_add_test(cmp, test_op_cmp_string_eq);
	tcase_add_test(cmp, test_op_cmp_string_false);
	suite_add_tcase(s, cmp);

	cmpint = tcase_create("op_cmp_int");
	tcase_add_checked_fixture(cmpint, setup_without_fd, teardown);
	tcase_set_timeout(cmpint, timeout);
	tcase_add_test(cmpint, test_op_cmp_int_eq);
	tcase_add_test(cmpint, test_op_cmp_int_ne);
	tcase_add_test(cmpint, test_op_cmp_int_le);
	tcase_add_test(cmpint, test_op_cmp_int_lt);
	tcase_add_test(cmpint, test_op_cmp_int_ge);
	tcase_add_test(cmpint, test_op_cmp_int_gt);
	suite_add_tcase(s, cmpint);

	resolvedfd = tcase_create("op_resolvedfd");
	tcase_add_checked_fixture(resolvedfd, setup_path, teardown);
	tcase_set_timeout(resolvedfd, timeout);
	tcase_add_test(resolvedfd, test_op_resolvedfd_eq);
	tcase_add_test(resolvedfd, test_op_resolvedfd_neq);
	suite_add_tcase(s, resolvedfd);

	nr = tcase_create("op_nr");
	tcase_add_checked_fixture(nr, setup_without_fd, teardown);
	tcase_set_timeout(nr, timeout);
	tcase_add_test(nr, test_op_nr);
	suite_add_tcase(s, nr);

	copy = tcase_create("op_copy");
	tcase_add_test(copy, test_op_copy);
	suite_add_tcase(s, copy);

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

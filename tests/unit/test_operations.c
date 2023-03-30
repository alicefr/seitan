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

#include "gluten.h"
#include "operations.h"
#include "common.h"
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
	socklen_t len;
	int fd;

	len = sizeof(char) * 108;
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ck_assert_int_ge(fd, 0);
	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sun_path, "/tmp/test.sock");
	addr.sun_family = AF_UNIX;
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_connect;
	at->args[0] = (void *)(long)fd;
	at->args[1] = (void *)&addr;
	at->args[2] = (void *)(long)len;
	at->install_filter = install_notification_filter;
	setup();
}

START_TEST(test_act_continue)
{
	struct op operations[] = {
		{ .type = OP_CONT },
	};
	int ret = do_operations(NULL, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	ck_assert_int_eq(at->err, 0);
}
END_TEST

START_TEST(test_act_block)
{
	struct op operations[] = {
		{
			.type = OP_BLOCK,
			.block = { .error = -1 },
		},
	};
	int ret = do_operations(NULL, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	/*
	 * The tests use getpid that returns the error with ret and it is always
	 * successful
	 */
	check_target_result(operations[0].block.error, 1, false);
}
END_TEST

START_TEST(test_act_return)
{
	struct op operations[] = {
		{
			.type = OP_RETURN,
			.ret = { .type = IMMEDIATE, .value = 1 },
		},
	};
	int ret = do_operations(NULL, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0, false);
}
END_TEST

START_TEST(test_act_return_ref)
{
	int64_t v = 2;
	uint16_t offset = 4;
	struct op operations[] = {
		{
			.type = OP_RETURN,
			.ret = { .type = REFERENCE, .value_off = offset },
		},
	};
	memcpy((uint16_t *)&tmp_data + offset, &v, sizeof(v));

	int ret = do_operations(&tmp_data, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(v, 0, false);
}
END_TEST

START_TEST(test_act_call)
{
	struct op operations[] = {
		{
			.type = OP_CALL,
			.call = { .nr = __NR_getppid, .has_ret = false },
		},
		{ .type = OP_CONT },
	};
	int ret = do_operations(NULL, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0, true);
}
END_TEST

START_TEST(test_act_call_ret)
{
	struct op operations[] = {
		{
			.type = OP_CALL,
			.call = { .nr = __NR_getppid,
				  .has_ret = true,
				  .ret_off = 2 },
		},
		{ .type = OP_CONT },
	};
	int ret = do_operations(&tmp_data, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	long r;
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0, true);
	memcpy(&r, &tmp_data[2], sizeof(r));
	ck_assert_int_eq(r, getpid());
}
END_TEST

static void test_inject(struct op operations[], int n, bool reference)
{
	uint16_t new_off = 2, old_off = 4;
	int fd_inj;
	int test_fd = 3;
	int ret;

	fd_inj = create_test_fd();
	ck_assert_int_ge(fd_inj, 0);
	if (reference) {
		memcpy((uint16_t *)&tmp_data + new_off, &fd_inj,
		       sizeof(fd_inj));
		memcpy((uint16_t *)&tmp_data + old_off, &test_fd,
		       sizeof(test_fd));

		operations[0].inj.newfd.fd_off = new_off;
		operations[0].inj.newfd.type = REFERENCE;
		operations[0].inj.oldfd.fd_off = old_off;
		operations[0].inj.oldfd.type = REFERENCE;
	} else {
		operations[0].inj.newfd.fd = fd_inj;
		operations[0].inj.newfd.type = IMMEDIATE;
		operations[0].inj.oldfd.fd = test_fd;
		operations[0].inj.oldfd.type = IMMEDIATE;
	}

	ret = do_operations(&tmp_data, operations, &req,n, -1, notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_fd(pid, test_fd);
}

START_TEST(test_act_inject_a)
{
	struct op operations[] = { { .type = OP_INJECT_A } };
	test_inject(operations, sizeof(operations) / sizeof(operations[0]), false);
}
END_TEST

START_TEST(test_act_inject_a_ref)
{
	struct op operations[] = { { .type = OP_INJECT_A } };
	test_inject(operations, sizeof(operations) / sizeof(operations[0]), true);
}
END_TEST

START_TEST(test_act_inject)
{
	struct op operations[] = { { .type = OP_INJECT } };
	test_inject(operations, sizeof(operations) / sizeof(operations[0]), false);
}
END_TEST

START_TEST(test_act_inject_ref)
{
	struct op operations[] = { { .type = OP_INJECT } };
	test_inject(operations, sizeof(operations) / sizeof(operations[0]), true);
}
END_TEST

START_TEST(test_op_copy)
{
	struct op operations[] = {
		{ .type = OP_COPY_ARGS },
		{
			.type = OP_RETURN,
			.ret = { .type = IMMEDIATE, .value = 0 },
		},
	};
	struct op_copy_args *o = &operations[0].copy;
	struct sockaddr_un *addr;
	socklen_t *len, expect;
	int ret;

	o->args[0] = (struct copy_arg){ .args_off = 0,
					.type = IMMEDIATE,
					.size = sizeof(int) };
	o->args[1] =
		(struct copy_arg){ .args_off = sizeof(int) / sizeof(uint16_t),
				   .type = REFERENCE,
				   .size = sizeof(struct sockaddr_un) };
	o->args[2] = (struct copy_arg){ .args_off = o->args[1].args_off +
						    sizeof(struct sockaddr_un) /
							    sizeof(uint16_t),
					.type = IMMEDIATE,
					.size = sizeof(socklen_t) };
	ret = do_operations(&tmp_data, operations, &req,
			    sizeof(operations) / sizeof(operations[0]), -1,
			    notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(0, 0, false);
	addr = (struct sockaddr_un *)(tmp_data + o->args[1].args_off);
	ck_assert_str_eq(addr->sun_path, "/tmp/test.sock");
	ck_assert(addr->sun_family == AF_UNIX);
	expect = sizeof(addr->sun_path);
	len = (socklen_t *)(tmp_data + o->args[2].args_off);
	ck_assert_msg(*len == expect, "expect len %x to be equal to %x", *len,
		      expect);
}
END_TEST

START_TEST(test_op_cmp_eq)
{
	char s[30] = "Hello Test!!";
	struct op operations[] = {
		{ .type = OP_CMP,
		  .cmp = { .s1_off = 0,
			   .s2_off = sizeof(s) / sizeof(uint16_t),
			   .size = sizeof(s),
			   .jmp = 2 } },
		{ .type = OP_CONT },
		{ .type = OP_END },
		{ .type = OP_BLOCK, .block = { .error = -1 } },
	};
	int ret;

	memcpy((uint16_t *)&tmp_data + operations[0].cmp.s1_off, &s, sizeof(s));
	memcpy((uint16_t *)&tmp_data + operations[0].cmp.s2_off, &s, sizeof(s));

	ret = do_operations(&tmp_data, operations, &req,
			    sizeof(operations) / sizeof(operations[0]), -1,
			    notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	ck_assert_int_eq(at->err, 0);
}
END_TEST

START_TEST(test_op_cmp_neq)
{
	char s1[30] = "Hello Test!!";
	char s2[30] = "Hello World!!";
	struct op operations[] = {
		{ .type = OP_CMP,
		  .cmp = { .s1_off = 0,
			   .s2_off = sizeof(s1) / sizeof(uint16_t),
			   .size = sizeof(s1),
			   .jmp = 2 } },
		{ .type = OP_CONT },
		{ .type = OP_END },
		{ .type = OP_BLOCK, .block = { .error = -1 } },
	};
	int ret;

	memcpy((uint16_t *)&tmp_data + operations[0].cmp.s1_off, &s1,
	       sizeof(s1));
	memcpy((uint16_t *)&tmp_data + operations[0].cmp.s2_off, &s2,
	       sizeof(s2));

	ret = do_operations(&tmp_data, operations, &req,
			    sizeof(operations) / sizeof(operations[0]), -1,
			    notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(-1, 1, false);
}
END_TEST

START_TEST(test_op_resolvedfd_eq)
{
	struct op operations[] = {
		{ .type = OP_RESOLVEDFD,
		  .resfd = { .fd_off = 0,
			     .path_off = sizeof(int) / sizeof(uint16_t),
			     .path_size = sizeof(path),
			     .jmp = 2 } },
		{ .type = OP_CONT },
		{ .type = OP_END },
		{ .type = OP_BLOCK, .block = { .error = -1 } },
	};

	memcpy((uint16_t *)&tmp_data + operations[0].resfd.fd_off, &at->fd,
	       sizeof(at->fd));
	memcpy((uint16_t *)&tmp_data + operations[0].resfd.path_off, &path,
	       sizeof(path));
	int ret = do_operations(&tmp_data, operations, &req,
				sizeof(operations) / sizeof(operations[0]), pid,
				notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(-1, 1, false);
}
END_TEST

START_TEST(test_op_resolvedfd_neq)
{
	char path2[] = "/tmp/seitan-test-wrong";
	struct op operations[] = {
		{ .type = OP_RESOLVEDFD,
		  .resfd = { .fd_off = 0,
			     .path_off = sizeof(int) / sizeof(uint16_t),
			     .path_size = sizeof(path2),
			     .jmp = 2 } },
		{ .type = OP_CONT },
		{ .type = OP_END },
		{ .type = OP_BLOCK, .block = { .error = -1 } },
	};
	memcpy((uint16_t *)&tmp_data + operations[0].resfd.fd_off, &at->fd,
	       sizeof(at->fd));
	memcpy((uint16_t *)&tmp_data + operations[0].resfd.path_off, &path2,
	       sizeof(path2));
	int ret = do_operations(&tmp_data, operations, &req,
				sizeof(operations) / sizeof(operations[0]), pid,
				notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
}
END_TEST


Suite *op_call_suite(void)
{
	Suite *s;
	int timeout = 30;
	TCase *cont, *block, *ret, *call, *cmp, *resolvedfd;
	TCase *inject, *inject_a;
	TCase *copy;

	s = suite_create("Perform operations");

	cont = tcase_create("a_continue");
	tcase_add_checked_fixture(cont, setup_without_fd, teardown);
	tcase_set_timeout(cont, timeout);
	tcase_add_test(cont, test_act_continue);
	suite_add_tcase(s, cont);

	ret = tcase_create("a_return");
	tcase_add_checked_fixture(ret, setup_without_fd, teardown);
	tcase_set_timeout(ret, timeout);
	tcase_add_test(ret, test_act_return);
	tcase_add_test(ret, test_act_return_ref);
	suite_add_tcase(s, ret);

	block = tcase_create("a_block");
	tcase_add_checked_fixture(block, setup_without_fd, teardown);
	tcase_set_timeout(block, timeout);
	tcase_add_test(block, test_act_block);
	suite_add_tcase(s, block);

	call = tcase_create("a_call");
	tcase_add_checked_fixture(call, setup_without_fd, teardown);
	tcase_set_timeout(call, timeout);
	tcase_add_test(call, test_act_call);
	tcase_add_test(call, test_act_call_ret);
	suite_add_tcase(s, call);

	inject = tcase_create("a_inject");
	tcase_add_checked_fixture(inject, setup_fd, teardown);
	tcase_set_timeout(inject, timeout);
	tcase_add_test(inject, test_act_inject);
	tcase_add_test(inject, test_act_inject_ref);
	suite_add_tcase(s, inject);

	inject_a = tcase_create("a_inject_a");
	tcase_add_checked_fixture(inject_a, setup_fd, teardown);
	tcase_set_timeout(inject_a, timeout);
	tcase_add_test(inject_a, test_act_inject_a);
	tcase_add_test(inject_a, test_act_inject_a_ref);
	suite_add_tcase(s, inject_a);

	copy = tcase_create("op_copy");
	tcase_add_checked_fixture(copy, setup_target_connect, teardown);
	tcase_set_timeout(copy, 120);
	tcase_add_test(copy, test_op_copy);
	suite_add_tcase(s, copy);

	cmp = tcase_create("op_cmp");
	tcase_add_checked_fixture(cmp, setup_without_fd, teardown);
	tcase_set_timeout(cmp, timeout);
	tcase_add_test(cmp, test_op_cmp_eq);
	tcase_add_test(cmp, test_op_cmp_neq);
	suite_add_tcase(s, cmp);

	resolvedfd = tcase_create("op_resolvedfd");
	tcase_add_checked_fixture(resolvedfd, setup_path, teardown);
	tcase_set_timeout(resolvedfd, timeout);
	tcase_add_test(resolvedfd, test_op_resolvedfd_eq);
	tcase_add_test(resolvedfd, test_op_resolvedfd_neq);
	suite_add_tcase(s, resolvedfd);

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

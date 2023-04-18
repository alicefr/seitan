/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include <check.h>

#include "gluten.h"
#include "common.h"
#include "testutil.h"
#include "filter.h"
#include "disasm.h"

static int generate_install_filter(struct args_target *at)
{
	struct bpf_call calls[1];
	struct syscall_entry table[] = {
		{ .count = 1, .nr = at->nr, .entry = &calls[0] }
	};
	struct sock_filter filter[30];
	unsigned int size;

	memcpy(&calls[0].args, &at->args, sizeof(calls[0].args));
	size = create_bfp_program(table, filter, 1);
	bpf_disasm_all(filter, size);
	return install_filter(filter, size);
}

START_TEST(no_args)
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getpid;
	set_args_no_check(at);
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}
END_TEST

static void test_with_getsid(enum arg_cmp cmp, int v)
{
	int id = 0x10;
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getsid;
	set_args_no_check(at);
	at->args[0].type = U32;
	at->args[0].value.v32 = id;
	at->args[0].cmp = cmp;
	if (cmp == EQ)
		at->targs[0] = (void *)(long)id;
	else
		at->targs[0] = (void *)(long)v;
	at->install_filter = generate_install_filter;
	setup();
}

START_TEST(with_getsid)
{
	test_with_getsid(EQ, 0);
}
END_TEST

START_TEST(with_getsid_gt)
{
	test_with_getsid(GT, 0x100);
}
END_TEST

START_TEST(with_getsid_lt)
{
	test_with_getsid(LE, 0x1);
}
END_TEST

START_TEST(with_getsid_ge)
{
	test_with_getsid(GE, 0x10);
}
END_TEST

START_TEST(with_getsid_le)
{
	test_with_getsid(LE, 0x10);
}
END_TEST

START_TEST(with_getpriority)
{
	int which = 0x12345;
	id_t who = PRIO_PROCESS;
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getpriority;
	set_args_no_check(at);
	at->args[0].value.v32 = which;
	at->args[0].type = U32;
	at->args[0].cmp = EQ;
	at->args[1].value.v32 = who;
	at->args[1].type = U32;
	at->args[1].cmp = EQ;
	at->targs[0] = (void *)(long)which;
	at->targs[1] = (void *)(long)who;
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}
END_TEST

static int target_lseek()
{
	int fd = open("/dev/zero", O_RDWR);

	/* Open the device on the target, but the arg0 isn't in the filter */
	ck_assert_int_ge(fd, 0);
	at->targs[0] = (void *)(long)fd;
	return target();
}

static void test_lseek(enum arg_cmp cmp, off_t offset, off_t v)
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_lseek;
	at->target = target_lseek;
	set_args_no_check(at);
	at->args[1].value.v64 = offset;
	at->args[1].type = U64;
	at->args[1].cmp = cmp;
	if (cmp == EQ)
		at->targs[1] = (void *)(long)offset;
	else
		at->targs[1] = (void *)(long)v;
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}

START_TEST(with_lseek_lo)
{
	test_lseek(EQ, 0x1, 0);
}
END_TEST

START_TEST(with_lseek_hi)
{
	test_lseek(EQ, 0x0000000100000000, 0);
}
END_TEST

START_TEST(with_lseek_lo_gt)
{
	test_lseek(GT, 0x1, 0x10);
}
END_TEST

START_TEST(with_lseek_hi_gt)
{
	test_lseek(GT, 0x100000000, 0x200000000);
}
END_TEST

START_TEST(with_lseek_lo_lt)
{
	test_lseek(LT, 0x10, 0x1);
}
END_TEST

START_TEST(with_lseek_hi_lt)
{
	test_lseek(LT, 0x200000000, 0x100000000);
}
END_TEST

START_TEST(with_lseek_lo_ge)
{
	test_lseek(GE, 0x1, 0x1);
}
END_TEST

START_TEST(with_lseek_hi_ge)
{
	test_lseek(GE, 0x100000000, 0x100000000);
}
END_TEST

START_TEST(with_lseek_lo_le)
{
	test_lseek(LE, 0x1, 0x1);
}
END_TEST

START_TEST(with_lseek_hi_le)
{
	test_lseek(LE, 0x200000000, 0x200000000);
}
END_TEST

START_TEST(with_open_and)
{
	char pathname[] = "test-abcdef";
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_open;
	set_args_no_check(at);
	at->args[1].value.v32 = O_CLOEXEC;
	at->args[1].op2.v32 = O_CLOEXEC;
	at->args[1].type = U32;
	at->args[1].cmp = AND_EQ;
	at->targs[0] = (void *)(long)&pathname;
	at->targs[1] =
		(void *)(long)(O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY);
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}
END_TEST

static void test_prctl_and(uint64_t v, uint64_t mask, uint64_t res,
			   enum arg_cmp cmp)
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_prctl;
	set_args_no_check(at);
	at->args[1].value.v64 = res;
	at->args[1].op2.v64 = mask;
	at->args[1].type = U64;
	at->args[1].cmp = cmp;
	at->targs[0] = (void *)(long)1;
	at->targs[1] = (void *)(long)v;
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}

START_TEST(with_prctl_and_lo)
{
	test_prctl_and(0x11111111, 0x1, 0x1, AND_EQ);
}
END_TEST

START_TEST(with_prctl_and_hi)
{
	test_prctl_and(0x1111111100000000, 0x100000000, 0x100000000, AND_EQ);
}
END_TEST

Suite *op_call_suite(void)
{
	Suite *s;
	int timeout = 30;
	TCase *simple, *args32, *args64, *cmp32, *cmp64;
	TCase *andop32, *andop64;

	s = suite_create("Test filter with target");

	simple = tcase_create("no args");
	tcase_add_checked_fixture(simple, NULL, teardown);
	tcase_set_timeout(simple, timeout);
	tcase_add_test(simple, no_args);
	suite_add_tcase(s, simple);

	args32 = tcase_create("with args 32 bit");
	tcase_add_checked_fixture(args32, NULL, teardown);
	tcase_set_timeout(args32, timeout);
	tcase_add_test(args32, with_getsid);
	tcase_add_test(args32, with_getpriority);
	suite_add_tcase(s, args32);

	args64 = tcase_create("with args 64 bit");
	tcase_add_checked_fixture(args64, NULL, teardown);
	tcase_set_timeout(args32, timeout);
	tcase_add_test(args64, with_lseek_lo);
	tcase_add_test(args64, with_lseek_hi);
	suite_add_tcase(s, args64);

	cmp32 = tcase_create("with args 32 bit and comparison operations");
	tcase_add_checked_fixture(cmp32, NULL, teardown);
	tcase_set_timeout(cmp32, timeout);
	tcase_add_test(cmp32, with_getsid_gt);
	tcase_add_test(cmp32, with_getsid_lt);
	tcase_add_test(cmp32, with_getsid_ge);
	tcase_add_test(cmp32, with_getsid_le);
	suite_add_tcase(s, cmp32);

	cmp64 = tcase_create("with args 64 bit and comparison operations");
	tcase_add_checked_fixture(cmp64, NULL, teardown);
	tcase_set_timeout(cmp64, timeout);
	tcase_add_test(cmp64, with_lseek_lo_gt);
	tcase_add_test(cmp64, with_lseek_hi_gt);
	tcase_add_test(cmp64, with_lseek_lo_lt);
	tcase_add_test(cmp64, with_lseek_hi_lt);
	tcase_add_test(cmp64, with_lseek_lo_ge);
	tcase_add_test(cmp64, with_lseek_hi_ge);
	tcase_add_test(cmp64, with_lseek_lo_le);
	tcase_add_test(cmp64, with_lseek_hi_le);
	suite_add_tcase(s, cmp64);

	andop32 = tcase_create("with and operation and 32 bits");
	tcase_add_checked_fixture(andop32, NULL, teardown);
	tcase_set_timeout(andop32, timeout);
	tcase_add_test(andop32, with_open_and);
	suite_add_tcase(s, andop32);

	andop64 = tcase_create("with and operation and 64 bits");
	tcase_add_checked_fixture(andop64, NULL, teardown);
	tcase_set_timeout(andop64, timeout);
	tcase_add_test(andop64, with_prctl_and_lo);
	tcase_add_test(andop64, with_prctl_and_hi);
	suite_add_tcase(s, andop64);

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

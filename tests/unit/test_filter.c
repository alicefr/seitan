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
	unsigned int i;
	struct bpf_call calls[1];
	struct syscall_entry table[] = {
		{ .count = 1, .nr = at->nr, .entry = &calls[0] }
	};
	struct sock_filter filter[30];
	unsigned int size;

	for (i = 0; i < 6; i++) {
		if (at->args[i] == NULL) {
			calls[0].args[i].type = NO_CHECK;
			continue;
		}
		switch (at->arg_type[i]) {
		case U32:
			calls[0].args[i].value.v32 = (uint32_t)at->args[i];
			calls[0].args[i].type = U32;
			break;
		case U64:
			calls[0].args[i].value.v64 = (uint64_t)at->args[i];
			calls[0].args[i].type = U64;
			break;
		case NO_CHECK:
			calls[0].args[i].type = NO_CHECK;
			break;
		}
	}
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

START_TEST(with_getsid)
{
	int id = 12345;
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getsid;
	set_args_no_check(at);
	at->args[0] = &id;
	at->arg_type[0] = U32;
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}
END_TEST

START_TEST(with_getpriority)
{
	int which = 12345;
	id_t who = PRIO_PROCESS;
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getpriority;
	set_args_no_check(at);
	at->args[0] = &which;
	at->arg_type[0] = U32;
	at->args[1] = &who;
	at->arg_type[0] = U32;
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
	at->args[0] = fd;
	return target();
}

static void test_lseek(off_t offset)
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_lseek;
	at->target = target_lseek;
	set_args_no_check(at);
	at->args[1] = offset;
	at->arg_type[1] = U64;
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}

START_TEST(with_lseek_lo)
{
	test_lseek(0x1);
}
END_TEST

START_TEST(with_lseek_hi)
{
	test_lseek(0x0000000100000000);
}
END_TEST

Suite *op_call_suite(void)
{
	Suite *s;
	int timeout = 30;
	TCase *simple, *args32, *args64;

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

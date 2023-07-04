/* SPDX-License-Identifier: GPL-2.0-or-later
* Copyright 2023 Red Hat GmbH
* Author: Alice Frosi <afrosi@redhat.com>
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include <check.h>

#include "common/gluten.h"
#include "common/common.h"
#include "testutil.h"
#include "cooker/filter.h"
#include "debug/disasm.h"

char tfilter[] = "/tmp/test-filter.bpf";

static int generate_install_filter(struct args_target *at)
{
	struct sock_filter filter[SIZE_FILTER];
	unsigned int size;
	bool has_arg = false;

	filter_notify(at->nr);
	for (unsigned int i = 0; i < 6; i++) {
		if (at->filter_args[i]) {
			filter_add_check(&at->bpf_fields[i]);
			has_arg = true;
		}
	}
	if(has_arg)
		filter_flush_args(at->nr);
	filter_write(tfilter);
	size = read_filter(filter, tfilter);
	fprintf(stderr, "size %d\n", size);
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

static void add_filter_arg32(struct args_target *at, int pos, uint32_t v,
			     uint32_t op2, enum bpf_cmp cmp)
{
	at->filter_args[pos] = true;
	at->bpf_fields[pos].arg = pos;
	at->bpf_fields[pos].value.v32 = v;
	at->bpf_fields[pos].op2.v32 = op2;
	at->bpf_fields[pos].type = BPF_U32;
	at->bpf_fields[pos].cmp = cmp;
}

static void add_filter_arg64(struct args_target *at, int pos, uint64_t v,
			     uint64_t op2, enum bpf_cmp cmp)
{
	at->filter_args[pos] = true;
	at->bpf_fields[pos].arg = pos;
	at->bpf_fields[pos].value.v64 = v;
	at->bpf_fields[pos].op2.v64 = op2;
	at->bpf_fields[pos].type = BPF_U64;
	at->bpf_fields[pos].cmp = cmp;
}


struct t32bit_getsid_data_t {
	enum bpf_cmp cmp;
	int v;
	int op;
};

struct t32bit_getsid_data_t t32bit_getsid_data[] = {
	{ EQ, 0x1, 0x1 },   { GT, 0x10, 0x1 }, { LT, 0x1, 0x10 },
	{ LE, 0x1, 0x10 },  { GE, 0x10, 0x1 }, { GE, 0x10, 0x10 },
	{ LE, 0x10, 0x10 },
};

START_TEST(test_with_getsid)
{
	enum bpf_cmp cmp = t32bit_getsid_data[_i].cmp;
	int v = t32bit_getsid_data[_i].v;
	int op = t32bit_getsid_data[_i].op;

	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getsid;
	set_args_no_check(at);
	at->targs[0] = (void *)(long)v;
	add_filter_arg32(at, 0, op, 0, cmp);
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
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

	at->targs[0] = (void*)(long)which;
	add_filter_arg32(at, 0, which, 0, EQ);
	at->targs[1] = (void*)(long)who;
	add_filter_arg32(at, 1, who, 0, EQ);

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

struct t64b_lseek_data_t {
	enum bpf_cmp cmp;
	off_t offset;
	off_t v;
};

struct t64b_lseek_data_t t64b_lseek_data[] = {
	{ EQ, 0x1, 0 },	   { EQ, 0x0000000100000000, 0 },
	{ GT, 0x10, 0x1 }, { GT, 0x200000000, 0x100000000 },
	{ LT, 0x1, 0x10 }, { LT, 0x100000000, 0x200000000 },
	{ GE, 0x1, 0x1 },  { GE, 0x100000000, 0x100000000 },
	{ GE, 0x2, 0x1 },  { GE, 0x200000000, 0x100000000 },
	{ LE, 0x1, 0x1 },  { LE, 0x200000000, 0x200000000 },
	{ LE, 0x1, 0x2 },  { LE, 0x100000000, 0x200000000 },
};

START_TEST(test_lseek)
{
	enum bpf_cmp cmp = t64b_lseek_data[_i].cmp;
	off_t offset = t64b_lseek_data[_i].offset;
	off_t v = t64b_lseek_data[_i].v;

	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_lseek;
	at->target = target_lseek;
	set_args_no_check(at);
	at->targs[1] = (void*)(long)offset;
	if (cmp == EQ)
		add_filter_arg64(at, 1, offset, 0, cmp);
	else
		add_filter_arg64(at, 1, v, 0, cmp);

	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}
END_TEST

struct topen_and_data_t {
	uint32_t v;
	uint32_t mask;
	uint32_t res;
	enum bpf_cmp cmp;
};

struct topen_and_data_t topen_and_data[] = {
	{ O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY, O_CLOEXEC, O_CLOEXEC,
	  AND_EQ },
	{ O_RDONLY | O_NONBLOCK | O_DIRECTORY, O_CLOEXEC, O_CLOEXEC, AND_NE },
};

START_TEST(test_open_and)
{
	uint32_t v = topen_and_data[_i].v;
	uint32_t mask = topen_and_data[_i].mask;
       	uint32_t res = topen_and_data[_i].res;
	enum bpf_cmp cmp = topen_and_data[_i].cmp;
	char pathname[] = "test-abcdef";

	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_open;
	set_args_no_check(at);
	add_filter_arg32(at, 1, res, mask, cmp);
	at->targs[0] = (void *)(long)&pathname;
	at->targs[1] = (void *)(long)v;
	at->install_filter = generate_install_filter;
	setup();
	mock_syscall_target();
}
END_TEST

struct tprctl_and_data_t {
	uint64_t v;
	uint64_t mask;
	uint64_t res;
	enum bpf_cmp cmp;
};

struct tprctl_and_data_t tprctl_and_data[] = {
	{ 0x11111111, 0x1, 0x1, AND_EQ },
	{ 0x1111111100000000, 0x100000000, 0x100000000, AND_EQ },
	{ 0x11111111, 0x1, 0x2, AND_NE },
	{ 0x1111111100000000, 0x100000000, 0x200000000, AND_NE },
};

START_TEST(test_prctl_and)
{
	uint64_t v = tprctl_and_data[_i].v;
	uint64_t mask = tprctl_and_data[_i].mask;
       	uint64_t res = tprctl_and_data[_i].res;
	enum bpf_cmp cmp = tprctl_and_data[_i].cmp;

	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_prctl;
	set_args_no_check(at);
	at->targs[0] = (void *)(long)1;
	at->targs[1] = (void *)(long)v;
	add_filter_arg64(at, 1, res, mask, cmp);
	at->install_filter = generate_install_filter;

	setup();
	mock_syscall_target();
}
END_TEST


Suite *op_call_suite(void)
{
	Suite *s;
	int timeout = 30;
	TCase *simple, *args32, *args64, *cmp32;
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
	tcase_add_test(args32, with_getpriority);
	suite_add_tcase(s, args32);

	args64 = tcase_create("with args 64 bit");
	tcase_add_checked_fixture(args64, NULL, teardown);
	tcase_set_timeout(args64, timeout);
	tcase_add_loop_test(args64, test_lseek, 0, ARRAY_SIZE(t64b_lseek_data));
	suite_add_tcase(s, args64);

	cmp32 = tcase_create("with args 32 bit and comparison operations");
	tcase_add_checked_fixture(cmp32, NULL, teardown);
	tcase_set_timeout(cmp32, timeout);
	tcase_add_loop_test(cmp32, test_with_getsid, 0,
			    ARRAY_SIZE(t32bit_getsid_data));
	suite_add_tcase(s, cmp32);

	andop32 = tcase_create("with and operation and 32 bits");
	tcase_add_checked_fixture(andop32, NULL, teardown);
	tcase_set_timeout(andop32, timeout);
	tcase_add_loop_test(andop32, test_open_and, 0,
			    ARRAY_SIZE(topen_and_data));
	suite_add_tcase(s, andop32);

	andop64 = tcase_create("with and operation and 64 bits");
	tcase_add_checked_fixture(andop64, NULL, teardown);
	tcase_set_timeout(andop64, timeout);
	tcase_add_loop_test(andop64, test_prctl_and, 0, ARRAY_SIZE(tprctl_and_data));
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

/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <check.h>

#include "operations.h"
#include "common/common.h"
#include "common/gluten.h"
#include "testutil.h"

static void setup_error_check()
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getpid;
	at->install_filter = install_notification_filter;
	setup();
}

static void setup_stderr()
{
	ck_stderr();
}

struct gluten_offset test_max_size_data[] = {
	{ OFFSET_DATA, DATA_SIZE },
	{ OFFSET_RO_DATA, RO_DATA_SIZE },
	{ OFFSET_SECCOMP_DATA, 6 },
	{ OFFSET_INSTRUCTION, INST_SIZE },
};

START_TEST(test_bound_check)
{
	struct op ops[] = {
		{ .type = OP_RETURN,
		  { .ret = { { test_max_size_data[_i].type,
			       test_max_size_data[_i].offset } } } },
		{ .type = OP_END, { { { 0 } } } },
	};
	write_instr(gluten, ops);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), -1);
}

START_TEST(test_write_op_return)
{
	struct gluten_offset offset = { OFFSET_RO_DATA, 0};
	struct gluten_offset ret_off = { OFFSET_DATA, DATA_SIZE };
	struct op ops[] = {
		{ OP_CALL, { .call = { offset } } },
	};
	char err_msg[200];
	struct syscall_desc_test {
		uint32_t nr : 9;
		uint32_t arg_count : 3;
		uint32_t has_ret : 1;
		uint32_t arg_deref : 6;
		struct gluten_offset context; /* struct context_desc [] */
		struct gluten_offset args[1];
	} syscall = {
		__NR_getppid, 0, 1, 0, { OFFSET_NULL, 0 }, { ret_off },
	};

	ck_stderr();
	sprintf(err_msg, "failed writing return value at %d", DATA_SIZE);
	ck_write_gluten(gluten, syscall, offset);
	write_instr(gluten, ops);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), -1);
	ck_error_msg(err_msg);
}

START_TEST(test_write_op_load)
{
	char a[30];
	char err_msg[200];
	struct op ops[] = {
		{ OP_LOAD,
		  { .load = { { OFFSET_SECCOMP_DATA, 1 },
			      { OFFSET_DATA, DATA_SIZE - 1 },
			      sizeof(a) } } },
	};

	ck_stderr();
	write_instr(gluten, ops);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), -1);
	ck_error_msg("offset limits are invalid");
}

struct gluten_offset test_max_size_read_data[] = {
	{ OFFSET_DATA, DATA_SIZE },
	{ OFFSET_RO_DATA, RO_DATA_SIZE },
	{ OFFSET_SECCOMP_DATA, 6 },
};

START_TEST(test_read_op_return)
{
	struct gluten_offset offset = { OFFSET_RO_DATA, 0 };
	struct return_desc desc = { { test_max_size_read_data[_i].offset,
				      test_max_size_read_data[_i].type },
				    { OFFSET_NULL, 0 },
				    false };
	struct op ops[] = {
		{ OP_RETURN, { .ret = { offset } } },
	};

	ck_stderr();
	ck_write_gluten(gluten, desc, offset);
	write_instr(gluten, ops);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), -1);
	ck_error_msg("offset limits are invalid");
}

static struct cmp_desc test_cmp_data[] = {
	{ .cmp = CMP_EQ, .x = { OFFSET_DATA, DATA_SIZE } },
	{ .cmp = CMP_EQ, .y = { OFFSET_DATA, DATA_SIZE } },
	{ .cmp = CMP_EQ, .x = { OFFSET_DATA, DATA_SIZE - 1 }, .size = 10 },
	{ .cmp = CMP_EQ, .y = { OFFSET_DATA, DATA_SIZE - 1 }, .size = 10 },
	{ .cmp = CMP_EQ, .jmp = { OFFSET_DATA, DATA_SIZE } },
};

START_TEST(test_op_cmp)
{
	struct gluten_offset offset = { OFFSET_RO_DATA, 0 };
	struct cmp_desc cmp = {
		test_cmp_data[_i].cmp,
		test_cmp_data[_i].size,
		{ test_cmp_data[_i].x.type, test_cmp_data[_i].x.offset },
		{ test_cmp_data[_i].y.type, test_cmp_data[_i].y.offset },
		test_cmp_data[_i].jmp
	};
	struct op ops[] = {
		{ OP_CMP, { .cmp = { offset } } },
	};

	ck_stderr();
	ck_write_gluten(gluten, cmp, offset);

	write_instr(gluten, ops);
	ck_assert_int_eq(eval(&gluten, &req, notifyfd), -1);
	ck_error_msg("offset limits are invalid");
}

struct ttargetnoexisting_data {
	struct op op;
	char err_msg[BUFSIZ];
};

Suite *error_suite(void)
{
	Suite *s;
	TCase *bounds, *gwrite, *gread, *gcmp;
	TCase *tnotexist;

	s = suite_create("Error handling");

	bounds = tcase_create("bound checks");
	tcase_add_loop_test(bounds, test_bound_check, 0,
			    ARRAY_SIZE(test_max_size_data));
	suite_add_tcase(s, bounds);

	gwrite = tcase_create("write gluten");
	tcase_add_checked_fixture(gwrite, setup_error_check, teardown);
	tcase_add_test(gwrite, test_write_op_return);
	tcase_add_test(gwrite, test_write_op_load);
	suite_add_tcase(s, gwrite);

	gread = tcase_create("read gluten");
	tcase_add_checked_fixture(gread, setup_error_check, teardown);
	tcase_add_loop_test(gread, test_read_op_return, 0,
			    ARRAY_SIZE(test_max_size_read_data));
	suite_add_tcase(s, gread);

	gcmp = tcase_create("compare gluten");
	tcase_add_checked_fixture(gcmp, setup_error_check, teardown);
	tcase_add_loop_test(gcmp, test_op_cmp, 0,
			    sizeof(test_cmp_data) / sizeof(test_cmp_data[0]));
	suite_add_tcase(s, gcmp);

	return s;
}

int main(void)
{
	int no_failed = 0;
	Suite *s;
	SRunner *runner;

	s = error_suite();
	runner = srunner_create(s);

	srunner_run_all(runner, CK_VERBOSE);
	no_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

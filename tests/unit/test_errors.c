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
		{ OP_RETURN, { { 0 } } },
		{ OP_END, { { 0 } } },
	};
	ops[0].op.ret.val.offset = test_max_size_data[_i].offset;
	ops[0].op.ret.val.type = test_max_size_data[_i].type;

	eval(&gluten, ops, &req, notifyfd);
}

START_TEST(test_write_op_return)
{
	struct op ops[] = {
		{ OP_CALL,
		  { .call = { .nr = __NR_getpid,
			      .has_ret = true,
			      .ret = { OFFSET_DATA, DATA_SIZE - 1 } } } },
		{ OP_END, { { 0 } } },
	};

	ck_assert_int_eq(eval(&gluten, ops, &req, notifyfd), -1);
}

START_TEST(test_write_op_load)
{
	char a[30];
	struct op ops[] = {
		{ OP_LOAD,
		  { .load = { { OFFSET_SECCOMP_DATA, 1 },
			      { OFFSET_DATA, DATA_SIZE - 1 },
			      sizeof(a) } } },
		{ OP_END, { { 0 } } },
	};

	ck_assert_int_eq(eval(&gluten, ops, &req, notifyfd), -1);
}

struct gluten_offset test_max_size_read_data[] = {
	{ OFFSET_DATA, DATA_SIZE },
	{ OFFSET_RO_DATA, RO_DATA_SIZE },
	{ OFFSET_SECCOMP_DATA, 6 },
};

START_TEST(test_read_op_return)
{
	struct op ops[] = {
		{ OP_RETURN, { { 0 } } },
		{ OP_END, { { 0 } } },
	};
	ops[0].op.ret.val.offset = test_max_size_read_data[_i].offset - 1;
	ops[0].op.ret.val.type = test_max_size_read_data[_i].type;

	ck_assert_int_eq(eval(&gluten, ops, &req, notifyfd), -1);
}

static struct op_cmp test_cmp_data[] = {
	{ { OFFSET_DATA, DATA_SIZE }, { OFFSET_DATA, 0 }, 1, CMP_EQ, 1 },
	{ { OFFSET_DATA, 0 }, { OFFSET_DATA, DATA_SIZE }, 1, CMP_EQ, 1 },
	{ { OFFSET_DATA, DATA_SIZE - 1 }, { OFFSET_DATA, 0 }, 10, CMP_EQ, 1 },
	{ { OFFSET_DATA, 0 }, { OFFSET_DATA, DATA_SIZE - 1 }, 10, CMP_EQ, 1 },
};

START_TEST(test_op_cmp)
{
	struct op ops[2];

	ops[0].type = OP_CMP;
	ops[0].op.cmp.x.offset = test_cmp_data[_i].x.offset;
	ops[0].op.cmp.x.type = test_cmp_data[_i].x.type;
	ops[0].op.cmp.y.offset = test_cmp_data[_i].y.offset;
	ops[0].op.cmp.y.type = test_cmp_data[_i].y.type;
	ops[0].op.cmp.size = test_cmp_data[_i].size;
	ops[0].op.cmp.jmp = test_cmp_data[_i].jmp;
	ops[1].type = OP_END;

	ck_assert_int_eq(eval(&gluten, ops, &req, notifyfd), -1);
}
static struct ttargetnoexisting_data {
	struct op op;
	char err_msg[BUFSIZ];
};

struct ttargetnoexisting_data test_target_noexisting_data[] = {
	{ { OP_CONT, { { 0 } } }, "the response id isn't valid" },
	{ { OP_BLOCK, { { 0 } } }, "the response id isn't valid" },
	{ { OP_RETURN, { { 0 } } }, "the response id isn't valid" },
	{ { OP_INJECT,
	    { .inject = { { OFFSET_DATA, 0 }, { OFFSET_DATA, 0 } } } },
	  "the response id isn't valid" },
	{ { OP_INJECT_A,
	    { .inject = { { OFFSET_DATA, 0 }, { OFFSET_DATA, 0 } } } },
	  "the response id isn't valid" },
	{ { OP_CALL, { .call = { __NR_getpid, false } } },
	  "the response id isn't valid" },
	{ { OP_LOAD,
	    { .load = { { OFFSET_SECCOMP_DATA, 1 }, { OFFSET_DATA, 0 }, 0 } } },
	  "error opening mem for" },
	{ { OP_RESOLVEDFD,
	    { .resfd = { { OFFSET_SECCOMP_DATA, 1 },
			 { OFFSET_DATA, 0 },
			 0,
			 0 } } },
	  "error reading /proc" },
};

START_TEST(test_target_noexisting)
{
	struct op ops[2];

	ops[0] = test_target_noexisting_data[_i].op;
	ops[1].type = OP_END;

	ck_assert_int_eq(eval(&gluten, ops, &req, notifyfd), -1);
	ck_error_msg(test_target_noexisting_data[_i].err_msg);
}

Suite *error_suite(void)
{
	Suite *s;
	TCase *bounds, *gwrite, *gread, *gcmp;
	TCase *tnotexist;

	s = suite_create("Error handling");

	bounds = tcase_create("bound checks");
	tcase_add_loop_test(bounds, test_bound_check, 0,
			    sizeof(test_max_size_data) /
				    sizeof(test_max_size_data[0]));
	suite_add_tcase(s, bounds);

	gwrite = tcase_create("write gluten");
	tcase_add_checked_fixture(gwrite, setup_error_check, teardown);
	tcase_add_test(gwrite, test_write_op_return);
	tcase_add_test(gwrite, test_write_op_load);
	suite_add_tcase(s, gwrite);

	gread = tcase_create("read gluten");
	tcase_add_checked_fixture(gread, setup_error_check, teardown);
	tcase_add_loop_test(gread, test_read_op_return, 0,
			    sizeof(test_max_size_read_data) /
				    sizeof(test_max_size_read_data[0]));
	suite_add_tcase(s, gread);

	gcmp = tcase_create("compare gluten");
	tcase_add_checked_fixture(gcmp, setup_error_check, teardown);
	tcase_add_loop_test(gcmp, test_op_cmp, 0,
			    sizeof(test_cmp_data) / sizeof(test_cmp_data[0]));
	suite_add_tcase(s, gcmp);

	tnotexist = tcase_create("target not existing");
	tcase_add_checked_fixture(tnotexist, setup_stderr, NULL);
	tcase_add_loop_test(tnotexist, test_target_noexisting, 0,
			    ARRAY_SIZE(test_target_noexisting_data));
	suite_add_tcase(s, tnotexist);

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

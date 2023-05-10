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

Suite *error_suite(void)
{
	Suite *s;
	TCase *bounds, *gwrite, *gread;

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

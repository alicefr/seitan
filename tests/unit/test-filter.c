#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <check.h>

#include "../../filter.h"
#include "../../disasm.h"

long nr = 42;

static bool filter_eq(struct sock_filter *f1, struct sock_filter *f2,
		      unsigned int n)
{
	unsigned i;
	for (i = 0; i < n; i++) {
		if (memcmp((void *)(f1 + i), (void *)(f2 + i),
			   sizeof(struct sock_filter)) != 0) {
			printf("expected:\n");
			bpf_disasm(f1[i], i);
			printf("got:\n");
			bpf_disasm(f2[i], i);
			return false;
		}
	}
	return true;
}

START_TEST(test_single_instr)
{
	unsigned int size;
	struct bpf_call calls[] = {
		{ .name = "test1" },
	};
	struct syscall_entry table[] = {
		{ .count = 1, .nr = nr, .entry = &calls[0] },
	};
	struct sock_filter result[10];
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		 	 (offsetof(struct seccomp_data, arch))),
		/* l1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 3),
		/* l2 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	 	 (offsetof(struct seccomp_data, nr))),
		/* l3 */ EQ(nr, 0, 1),
		/* l4 */ JUMPA(0),
		/* l5 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l6 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};

	size = create_bfp_program(table, result,
				  sizeof(calls) / sizeof(calls[0]));
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST

START_TEST(test_single_instr_two_args)
{
	unsigned int size;
	long nr = 42;
	struct bpf_call calls[] = {
		{
			.name = "test1",
			.args = { 0, 123, 321, 0, 0, 0 },
			.check_arg = { false, true, true, false, false, false },
		},
	};
	struct syscall_entry table[] = {
		{ .count = 1, .nr = nr, .entry = &calls[0] },
	};
	struct sock_filter result[10];
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 5),
		/* l2 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* l3 */ EQ(nr, 0, 3),
		/* l4 */ EQ(123, 3, 0),
		/* l5 */ EQ(321, 2, 0),
		/* l6 */ JUMPA(0),
		/* l7 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l8 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};

	size = create_bfp_program(table, result,
				  sizeof(calls) / sizeof(calls[0]));
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST

START_TEST(test_two_instr)
{
	unsigned int size;
	struct bpf_call calls[] = {
		{
			.name = "connect",
		},
		{
			.name = "bind",
		},
	};
	struct syscall_entry table[] = {
		{ .count = 1, .nr = 42, .entry = &calls[0] },
		{ .count = 1, .nr = 49, .entry = &calls[1] },
	};
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		 	 (offsetof(struct seccomp_data, arch))),
		/* l1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 6),
		/* l2 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	 	 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l3 */ JGE(49, 2, 0),
		/* ------- level0 -------- */
		/* l4 */ EQ(42, 0, 3),
		/* l5 */ JUMPA(2),
		/* l6 */ EQ(49, 0, 1),
		/* l7 */ JUMPA(0),
		/* l8 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l9 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_filter result[30];

	size = create_bfp_program(table, result,
				  sizeof(calls) / sizeof(calls[0]));
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST

START_TEST(test_multiple_instr_no_args)
{
	unsigned int size;
	struct bpf_call calls[] = { { .name = "test1"}, { .name = "test2"},
		{ .name = "test3"}, { .name = "test4"}, { .name = "test5"},
	};
	struct syscall_entry table[] = {
		{ .count = 1, .nr = 42, .entry = &calls[0] },
		{ .count = 1, .nr = 43, .entry = &calls[1] },
		{ .count = 1, .nr = 44, .entry = &calls[2] },
		{ .count = 1, .nr = 45, .entry = &calls[3] },
		{ .count = 1, .nr = 46, .entry = &calls[4] },
	};
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		 	 (offsetof(struct seccomp_data, arch))),
		/* l1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 17),
		/* l2 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	 	 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l3 */ JGE(46, 1, 0),
		/* ------- level1 -------- */
		/* l4 */ JGE(45, 2, 1),
		/* l5 */ JGE(46, 3, 3),
		/* ------- level2 -------- */
		/* l6 */ JGE(43, 5, 2),
		/* l7 */ JGE(45, 9, 6),
		/* l8 */ JGE(46, 8, 8),
		/* -------- leaves ------- */
		/* l9 */  EQ(42, 10, 9),
		/* l10 */ JUMPA(8),
		/* l11 */ EQ(43, 8, 7),
		/* l12 */ JUMPA(6),
		/* l13 */ EQ(44, 6, 5),
		/* l14 */ JUMPA(4),
		/* l15 */ EQ(45, 4, 3),
		/* l16 */ JUMPA(2),
		/* l17 */ EQ(46, 2, 1),
		/* l18 */ JUMPA(0),
		/* l19 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l20 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_filter result[sizeof(expected) / sizeof(expected[0]) + 10];

	size = create_bfp_program(table, result,
				  sizeof(calls) / sizeof(calls[0]));
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST


Suite *bpf_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Create BPF filter");
	tc_core = tcase_create("verify filter");

	tcase_add_test(tc_core, test_single_instr);
	tcase_add_test(tc_core, test_single_instr_two_args);
	tcase_add_test(tc_core,test_two_instr);
	tcase_add_test(tc_core,test_multiple_instr_no_args);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int no_failed = 0;
	Suite *s;
	SRunner *runner;

	s = bpf_suite();
	runner = srunner_create(s);

	srunner_run_all(runner, CK_NORMAL);
	no_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

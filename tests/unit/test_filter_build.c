/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <check.h>

#include "filter.h"
#include "disasm.h"

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
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 2),
		/* l2 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* l3 */ EQ(nr, 1, 0),
		/* l4 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l5 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};

	size = create_bfp_program(table, result,
				  sizeof(table) / sizeof(table[0]));
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
			.check_arg = { NO_CHECK, U32, U32, NO_CHECK, NO_CHECK,
				       NO_CHECK },
		},
	};
	struct syscall_entry table[] = {
		{ .count = 1, .nr = nr, .entry = &calls[0] },
	};
	struct sock_filter result[10];
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 8),
		/* l2 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* l3 */ EQ(nr, 0, 6),
		/* l4 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l5 */ EQ(123, 0, 2),
		/* l6 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l7 */ EQ(321, 0, 1),
		/* l8 */ JUMPA(2),
		/* l9 */ JUMPA(0),
		/* l10 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l11 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	size = create_bfp_program(table, result,
				  sizeof(table) / sizeof(table[0]));
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST

START_TEST(test_two_instr)
{
	unsigned int size;
	struct bpf_call calls[] = {
		{ .name = "test1" },
		{ .name = "test2" },
	};
	struct syscall_entry table[] = {
		{ .count = 1, .nr = 42, .entry = &calls[0] },
		{ .count = 1, .nr = 49, .entry = &calls[1] },
	};
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 4),
		/* l2 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l3 */ JGE(49, 1, 0),
		/* ------- leaves -------- */
		/* l4 */ EQ(42, 2, 1),
		/* l5 */ EQ(49, 1, 0),
		/* l6 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l7 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_filter result[30];

	size = create_bfp_program(table, result,
				  sizeof(table) / sizeof(table[0]));
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST

START_TEST(test_multiple_instr_no_args)
{
	unsigned int size;
	struct bpf_call calls[] = {
		{ .name = "test1" }, { .name = "test2" }, { .name = "test3" },
		{ .name = "test4" }, { .name = "test5" },
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
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 13),
		/* l2 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l3 */ JGE(46, 1, 0),
		/* ------- level1 -------- */
		/* l4 */ JGE(45, 2, 1),
		/* l5 */ JGE(46, 3, 2),
		/* ------- level2 -------- */
		/* l6 */ JGE(43, 4, 3),
		/* l7 */ JGE(45, 5, 4),
		/* l8 */ JGE(46, 6, 5),
		/* l9 */ JUMPA(5),
		/* -------- leaves ------- */
		/* l10 */ EQ(42, 5, 4),
		/* l11 */ EQ(43, 4, 3),
		/* l12 */ EQ(44, 3, 2),
		/* l13 */ EQ(45, 2, 1),
		/* l14 */ EQ(46, 1, 0),
		/* l20 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l21 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_filter result[sizeof(expected) / sizeof(expected[0]) + 10];

	size = create_bfp_program(table, result,
				  sizeof(table) / sizeof(table[0]));
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST

START_TEST(test_multiple_instr_with_args)
{
	unsigned int size;
	struct bpf_call calls[] = {
		{ .name = "test1",
		  .args = { 0, 123, 321, 0, 0, 0 },
		  .check_arg = { NO_CHECK, U32, U32, NO_CHECK, NO_CHECK,
				 NO_CHECK } },
		{ .name = "test2" },
		{ .name = "test3" },
		{ .name = "test4",
		  .args = { 0, 123, 321, 0, 0, 0 },
		  .check_arg = { NO_CHECK, U32, U32, NO_CHECK, NO_CHECK,
				 NO_CHECK } },
		{ .name = "test5" },
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
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 25),
		/* l2 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l3 */ JGE(46, 1, 0),
		/* ------- level1 -------- */
		/* l4 */ JGE(45, 2, 1),
		/* l5 */ JGE(46, 3, 2),
		/* ------- level2 -------- */
		/* l6 */ JGE(43, 4, 3),
		/* l7 */ JGE(45, 5, 4),
		/* l8 */ JGE(46, 6, 5),
		/* l9 */ JUMPA(17),
		/* -------- leaves ------- */
		/* l10 */ EQ(42, 4, 16),
		/* l11 */ EQ(43, 16, 15),
		/* l12 */ EQ(44, 15, 14),
		/* l13 */ EQ(45, 6, 13),
		/* l14 */ EQ(46, 13, 12),
		/* ------- args ---------- */
		/* l15 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l16 */ EQ(123, 0, 2),
		/* l17 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l18 */ EQ(321, 0, 1),
		/* l19 */ JUMPA(8), /* notify */
		/* l20 */ JUMPA(6),
		/* ----- end call44 ------ */
		/* l21 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l22 */ EQ(123, 0, 2),
		/* l23 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l24 */ EQ(321, 0, 1),
		/* l25 */ JUMPA(2), /* notify */
		/* l26 */ JUMPA(0),
		/* ----- end call46 ------ */
		/* l27 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l28 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_filter result[sizeof(expected) / sizeof(expected[0]) + 10];

	size = create_bfp_program(table, result,
				  sizeof(table) / sizeof(table[0]));
	//	bpf_disasm_all(result, size);
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST

START_TEST(test_multiple_instance_same_instr)
{
	unsigned int size;
	struct bpf_call calls[] = {
		{ .name = "test1",
		  .args = { 0, 123, 0, 0, 0, 0 },
		  .check_arg = { NO_CHECK, U32, NO_CHECK, NO_CHECK, NO_CHECK,
				 NO_CHECK } },
		{ .name = "test1",
		  .args = { 0, 0, 321, 0, 0, 0 },
		  .check_arg = { NO_CHECK, NO_CHECK, U32, NO_CHECK, NO_CHECK,
				 NO_CHECK } },
		{ .name = "test2" },
		{ .name = "test3" },
		{ .name = "test4",
		  .args = { 0, 123, 0, 0, 0, 0 },
		  .check_arg = { NO_CHECK, U32, NO_CHECK, NO_CHECK, NO_CHECK,
				 NO_CHECK } },
		{ .name = "test4",
		  .args = { 0, 0, 321, 0, 0, 0 },
		  .check_arg = { NO_CHECK, NO_CHECK, U32, NO_CHECK, NO_CHECK,
				 NO_CHECK } },
		{ .name = "test5" },
	};
	struct syscall_entry table[] = {
		{ .count = 2, .nr = 42, .entry = &calls[0] },
		{ .count = 1, .nr = 43, .entry = &calls[2] },
		{ .count = 1, .nr = 44, .entry = &calls[3] },
		{ .count = 2, .nr = 45, .entry = &calls[4] },
		{ .count = 1, .nr = 46, .entry = &calls[6] },
	};
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 27),
		/* l2 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l3 */ JGE(46, 1, 0),
		/* ------- level1 -------- */
		/* l4 */ JGE(45, 2, 1),
		/* l5 */ JGE(46, 3, 2),
		/* ------- level2 -------- */
		/* l6 */ JGE(43, 4, 3),
		/* l7 */ JGE(45, 5, 4),
		/* l8 */ JGE(46, 6, 5),
		/* l9 */ JUMPA(19),
		/* -------- leaves ------- */
		/* l10 */ EQ(42, 4, 18),
		/* l11 */ EQ(43, 18, 17),
		/* l12 */ EQ(44, 17, 16),
		/* l13 */ EQ(45, 6, 15),
		/* l14 */ EQ(46, 15, 14),
		/* ------- args ---------- */
		/* l15 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l16 */ EQ(123, 0, 1),
		/* l17 */ JUMPA(12), /* notify */
		/* l18 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l19 */ EQ(321, 0, 1),
		/* l20 */ JUMPA(9), /* notify */
		/* l21 */ JUMPA(7),
		/* ----- end call44 ------ */
		/* l22 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l23 */ EQ(123, 0, 1),
		/* l24 */ JUMPA(5), /* notify */
		/* l25 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l26 */ EQ(321, 0, 1),
		/* l27 */ JUMPA(2), /* notify */
		/* l28 */ JUMPA(0),
		/* l29 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l30 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_filter result[sizeof(expected) / sizeof(expected[0]) + 10];

	size = create_bfp_program(table, result,
				  sizeof(table) / sizeof(table[0]));
	ck_assert_uint_eq(size, sizeof(expected) / sizeof(expected[0]));
	ck_assert(filter_eq(expected, result,
			    sizeof(expected) / sizeof(expected[0])));
}
END_TEST

Suite *bpf_suite(void)
{
	Suite *s;
	TCase *tsingle_instr, *tmultiple_instr;

	s = suite_create("Create BPF filter");
	tsingle_instr = tcase_create("single instruction");
	tmultiple_instr = tcase_create("multiple instructions");

	tcase_add_test(tsingle_instr, test_single_instr);
	tcase_add_test(tsingle_instr, test_single_instr_two_args);
	tcase_add_test(tmultiple_instr, test_two_instr);
	tcase_add_test(tmultiple_instr, test_multiple_instr_no_args);
	tcase_add_test(tmultiple_instr, test_multiple_instr_with_args);
	tcase_add_test(tmultiple_instr, test_multiple_instance_same_instr);

	suite_add_tcase(s, tsingle_instr);
	suite_add_tcase(s, tmultiple_instr);

	return s;
}

int main(void)
{
	int no_failed = 0;
	Suite *s;
	SRunner *runner;

	s = bpf_suite();
	runner = srunner_create(s);

	srunner_run_all(runner, CK_VERBOSE);
	no_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

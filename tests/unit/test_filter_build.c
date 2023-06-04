/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <check.h>

#include "cooker/filter.h"
#include "disasm.h"
#include "testutil.h"

char tfilter[] = "/tmp/test-filter.bpf";

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
	struct sock_filter filter[10];
	unsigned int size;
	long nr = 42;
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 1, 0),
		/* l10 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l2 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* l3 */ EQ(nr, 1, 0),
		/* l4 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l5 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};

	filter_notify(nr);

	filter_write(tfilter);
	size = read_filter(filter, tfilter);
	ck_assert_uint_eq(size, ARRAY_SIZE(expected));
	ck_assert(filter_eq(expected, filter, ARRAY_SIZE(expected)));
}
END_TEST

START_TEST(test_single_instr_two_args)
{
	unsigned int size;
	long nr = 42;
	struct bpf_arg a1 = { .cmp = EQ,
			      .value = { .v32 = 0x123 },
			      .type = BPF_U32 };
	struct bpf_arg a2 = { .cmp = EQ,
			      .value = { .v32 = 0x321 },
			      .type = BPF_U32 };
	struct sock_filter result[20];
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 1, 0),
		/* l2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l3 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* l4 */ EQ(nr, 2, 0),
		/* l5 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l6 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* l7 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l8 */ EQ(0x123, 0, 2),
		/* l9 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l10 */ EQ(0x321, 0, 1),
		/* l11 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* l12 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	filter_notify(nr);
	filter_add_arg(1, a1);
	filter_add_arg(2, a2);
	filter_flush_args();

	filter_write(tfilter);
	size = read_filter(result, tfilter);

	ck_assert_uint_eq(size, ARRAY_SIZE(expected));
	ck_assert(filter_eq(expected, result, ARRAY_SIZE(expected)));
}
END_TEST

START_TEST(test_two_instr)
{
	unsigned int size;
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 1, 0),
		/* l2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l3 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l4 */ JGE(49, 1, 0),
		/* ------- leaves -------- */
		/* l5 */ EQ(42, 2, 1),
		/* l6 */ EQ(49, 1, 0),
		/* l7 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l8 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_filter result[30];
	filter_notify(42);
	filter_notify(49);

	filter_write(tfilter);
	size = read_filter(result, tfilter);

	ck_assert_uint_eq(size, ARRAY_SIZE(expected));
	ck_assert(filter_eq(expected, result, ARRAY_SIZE(expected)));
}
END_TEST

START_TEST(test_multiple_instr_no_args)
{
	unsigned int size;
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 1, 0),
		/* l2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l3 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l4 */ JGE(46, 1, 0),
		/* ------- level1 -------- */
		/* l5 */ JGE(45, 2, 1),
		/* l6 */ JGE(46, 3, 2),
		/* ------- level2 -------- */
		/* l7 */ JGE(43, 4, 3),
		/* l8 */ JGE(45, 5, 4),
		/* l9 */ JGE(46, 6, 5),
		/* l10 */ JUMPA(5),
		/* -------- leaves ------- */
		/* l11 */ EQ(42, 5, 4),
		/* l12 */ EQ(43, 4, 3),
		/* l13 */ EQ(44, 3, 2),
		/* l14 */ EQ(45, 2, 1),
		/* l15 */ EQ(46, 1, 0),
		/* l16 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l17 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_filter result[sizeof(expected) / sizeof(expected[0]) + 10];

	filter_notify(42);
	filter_notify(43);
	filter_notify(44);
	filter_notify(45);
	filter_notify(46);

	filter_write(tfilter);
	size = read_filter(result, tfilter);

	ck_assert_uint_eq(size, ARRAY_SIZE(expected));
	ck_assert(filter_eq(expected, result, ARRAY_SIZE(expected)));
}
END_TEST

START_TEST(test_multiple_instr_with_args)
{
	unsigned int size;
	struct bpf_arg a1 = { .cmp = EQ,
			      .value = { .v32 = 0x123 },
			      .type = BPF_U32 };
	struct bpf_arg a2 = { .cmp = EQ,
			      .value = { .v32 = 0x321 },
			      .type = BPF_U32 };
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 1, 0),
		/* l2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l3 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l4 */ JGE(46, 1, 0),
		/* ------- level1 -------- */
		/* l5 */ JGE(45, 2, 1),
		/* l6 */ JGE(46, 3, 2),
		/* ------- level2 -------- */
		/* l7 */ JGE(43, 4, 3),
		/* l8 */ JGE(45, 5, 4),
		/* l9 */ JGE(46, 6, 5),
		/* l10 */ JUMPA(5),
		/* -------- leaves ------- */
		/* l11 */ EQ(42, 6, 4),
		/* l12 */ EQ(43, 4, 3),
		/* l13 */ EQ(44, 3, 2),
		/* l14 */ EQ(45, 9, 1),
		/* l15 */ EQ(46, 1, 0),
		/* l16 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l17 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* ------- args ---------- */
		/* l18 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l19 */ EQ(0x123, 0, 2),
		/* l20 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l21 */ EQ(0x321, 0, 1),
		/* l22 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* l23 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* ----- end call42 ------ */
		/* l24 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l25 */ EQ(0x123, 0, 2),
		/* l26 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l27 */ EQ(0x321, 0, 1),
		/* l28 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* l29 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* ----- end call45 ------ */
	};
	struct sock_filter result[sizeof(expected) / sizeof(expected[0]) + 10];
	filter_notify(42);
	filter_add_arg(1, a1);
	filter_add_arg(2, a2);
	filter_flush_args();
	filter_notify(43);
	filter_notify(44);
	filter_notify(45);
	filter_add_arg(1, a1);
	filter_add_arg(2, a2);
	filter_flush_args();
	filter_notify(46);

	filter_write(tfilter);
	size = read_filter(result, tfilter);

	ck_assert_uint_eq(size, ARRAY_SIZE(expected));
	ck_assert(filter_eq(expected, result, ARRAY_SIZE(expected)));
}
END_TEST

START_TEST(test_multiple_instance_same_instr)
{
	unsigned int size;
	struct bpf_arg a1 = { .cmp = EQ,
			      .value = { .v32 = 0x123 },
			      .type = BPF_U32 };
	struct bpf_arg a2 = { .cmp = EQ,
			      .value = { .v32 = 0x321 },
			      .type = BPF_U32 };
	struct sock_filter expected[] = {
		/* l0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				  (offsetof(struct seccomp_data, arch))),
		/* l1 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 1, 0),
		/* l2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l3 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		/* ------- level0 -------- */
		/* l4 */ JGE(46, 1, 0),
		/* ------- level1 -------- */
		/* l5 */ JGE(45, 2, 1),
		/* l6 */ JGE(46, 3, 2),
		/* ------- level2 -------- */
		/* l7 */ JGE(43, 4, 3),
		/* l8 */ JGE(45, 5, 4),
		/* l9 */ JGE(46, 6, 5),
		/* l10 */ JUMPA(5),
		/* -------- leaves ------- */
		/* l11 */ EQ(42, 6, 4),
		/* l12 */ EQ(43, 4, 3),
		/* l13 */ EQ(44, 3, 2),
		/* l14 */ EQ(45, 10, 1),
		/* l15 */ EQ(46, 1, 0),
		/* l16 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* l17 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* ------- args ---------- */
		/* l18 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l19 */ EQ(0x123, 0, 1),
		/* l20 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* l21 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l22 */ EQ(0x321, 0, 1),
		/* l23 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* l24 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* ----- end call42 ------ */
		/* l25 */ LOAD(offsetof(struct seccomp_data, args[1])),
		/* l26 */ EQ(0x123, 0, 1),
		/* l27 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* l28 */ LOAD(offsetof(struct seccomp_data, args[2])),
		/* l29 */ EQ(0x321, 0, 1),
		/* l30 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* l31 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* ----- end call45 ------ */
	};
	struct sock_filter result[sizeof(expected) / sizeof(expected[0]) + 10];

	filter_notify(42);
	filter_add_arg(1, a1);
	filter_flush_args();
	filter_add_arg(2, a2);
	filter_flush_args();
	filter_notify(43);
	filter_notify(44);
	filter_notify(45);
	filter_add_arg(1, a1);
	filter_flush_args();
	filter_add_arg(2, a2);
	filter_flush_args();
	filter_notify(46);

	filter_write(tfilter);
	size = read_filter(result, tfilter);

	ck_assert_uint_eq(size, ARRAY_SIZE(expected));
	ck_assert(filter_eq(expected, result, ARRAY_SIZE(expected)));
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

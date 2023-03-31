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
#include "common.h"
#include "testutil.h"
#include "filter.h"

static int generate_install_filter(struct args_target *at)
{
	struct bpf_call calls[] = { {} };
	struct syscall_entry table[] = {
		{ .count = 1, .nr = at->nr, .entry = &calls[0] }
	};
	struct sock_filter filter[30];
	unsigned int size;

	size = create_bfp_program(table, filter, 1);
	return install_filter(filter, size);
}

void setup_build_filter()
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getpid;
	at->args[0] = NULL;
	at->install_filter = generate_install_filter;
	setup();
}

START_TEST(filter)
{
	continue_target();
}
END_TEST


Suite *op_call_suite(void)
{
	Suite *s;
	int timeout = 30;
	TCase *simple;

	s = suite_create("Test filter with target");

	simple = tcase_create("simple");
	tcase_add_checked_fixture(simple, setup_build_filter, teardown);
	tcase_set_timeout(simple, timeout);
	tcase_add_test(simple, filter);
	suite_add_tcase(s, simple);

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

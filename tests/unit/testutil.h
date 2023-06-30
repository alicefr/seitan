/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#ifndef TESTUTIL_H
#define TESTUTIL_H
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>

#include <check.h>
#include "cooker/filter.h"

#ifndef SEITAN_TEST
#define SEITAN_TEST
#endif
#include "common/gluten.h"

#define STACK_SIZE (1024 * 1024 / 8)
#define _EMPTY_ { .cont = { false } }
static inline void *test_gluten_write_ptr(struct gluten *g,
					  const struct gluten_offset x)
{
	ck_assert_msg(is_offset_valid(x), "offset out of bounds");

	switch (x.type) {
	case OFFSET_DATA:
		return (char *)g->data + x.offset;
	case OFFSET_RO_DATA:
		return (char *)g->ro_data + x.offset;
	case OFFSET_INSTRUCTION:
		return (struct op *)(g->inst) + x.offset;
	default:
		return NULL;
	}
}

#define write_instr(gluten, ops)                                              \
	do {                                                                  \
		struct gluten_offset x = { OFFSET_INSTRUCTION, 0 };           \
		memcpy(test_gluten_write_ptr(&gluten, x), &ops, sizeof(ops)); \
	} while (0)

#define ck_write_gluten(gluten, value, ref)                            \
	do {                                                           \
		void *p = test_gluten_write_ptr(&gluten, value);       \
		ck_assert_ptr_nonnull(p);                              \
		memcpy(p, &ref, sizeof(ref));                          \
	} while (0)

#define ck_read_gluten(gluten, value, ref)                       \
	do {                                                     \
		void *p = test_gluten_write_ptr(&gluten, value); \
		ck_assert_ptr_nonnull(p);                        \
		memcpy(&ref, p, sizeof(ref));                    \
	} while (0)
#define NS_NUM CONTEXT_TYPE_MAX - 3
struct args_target {
        long ret;
        int err;
        bool check_fd;
        bool open_path;
        int fd;
        int nr;
	bool filter_args[6];
	struct bpf_field bpf_fields[6];
	void *targs[6];
	void *tclone;
	bool ns[NS_NUM];
	int (*install_filter)(struct args_target *at);
	int (*target)(void *);
};

extern struct seccomp_notif req;
extern int notifyfd;
extern struct args_target *at;
extern int pipefd[2];
extern pid_t pid;
extern char path[PATH_MAX];
extern char stderr_buff[BUFSIZ];
extern char stdout_buff[BUFSIZ];

extern struct gluten gluten;

int target();
int create_test_fd();
int get_fd_notifier(pid_t pid);
void target_exit();
void check_target_fd(int pid, int fd);
bool has_fd(int pid, int fd);
void check_target_result(long ret, int err, bool ignore_ret);
void setup();
void teardown();
int install_notification_filter(struct args_target *at);
void continue_target();
void mock_syscall_target();
void set_args_no_check(struct args_target *at);
void check_target_result_nonegative();
void ck_error_msg(char *s);
void ck_stderr();
void ck_stdout();
int install_single_syscall(long nr);
int read_filter(struct sock_filter filter[], char *file);
#endif /* TESTUTIL_H */

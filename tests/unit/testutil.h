#ifndef TESTUTIL_H
#define TESTUTIL_H

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

static inline void *test_gluten_write_ptr(struct gluten *g,
					  const struct gluten_offset x)
{
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

struct args_target {
        long ret;
        int err;
        bool check_fd;
        bool open_path;
        int fd;
        int nr;
	struct arg args[6];
	void *targs[6];
	int (*install_filter)(struct args_target *at);
	int (*target)(void *);
};

extern struct seccomp_notif req;
extern int notifyfd;
extern struct args_target *at;
extern int pipefd[2];
extern pid_t pid;
extern char path[PATH_MAX];

extern struct gluten gluten;

int target();
pid_t do_clone(int (*fn)(void *), void *arg);
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
#endif /* TESTUTIL_H */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>

#include <check.h>

#include "../../gluten.h"
#include "../../actions.h"
#include "../../common.h"

struct args_target {
	long ret;
	int err;
};

struct seccomp_notif req;
int notifyfd;
struct args_target *at;
int pipefd[2];
int nr = __NR_getpid;

static int install_notification_filter()
{
	int fd;
	/* filter a single syscall for the tests */
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog;

	prog.filter = filter;
	prog.len = (unsigned short)(sizeof(filter) / sizeof(filter[0]));
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("prctl");
		return -1;
	}
	if ((fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
			  SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog)) < 0) {
		perror("seccomp");
		return -1;
	}
	return fd;
}

static int target()
{
	int ret = 0;
	int fd;

	close(pipefd[0]);
	fd = install_notification_filter();
	if (fd < 0) {
		return -1;
	}
	at->ret = getpid();
	at->err = errno;

	write(pipefd[1], &ret, 1);
	close(pipefd[1]);
	exit(0);
}

static pid_t do_clone(int (*fn)(void *), void *arg)
{
	char stack[STACK_SIZE];
	pid_t child;
	int flags = SIGCHLD;

	child = clone(fn, stack + sizeof(stack), flags, arg);
	if (child == -1) {
		perror("clone");
		return -1;
	}
	return child;
}

int get_fd_notifier(pid_t pid)
{
	char path[PATH_MAX + 1];
	int pidfd, notifier;
	int fd = -1;

	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	while (fd < 0) {
		sleep(2);
		fd = find_fd_seccomp_notifier(path);
	}
	ck_assert_int_ge(fd, 0);
	pidfd = syscall(SYS_pidfd_open, pid, 0);
	ck_assert_msg(pidfd >= 0, strerror(errno));
	sleep(1);
	notifier = syscall(SYS_pidfd_getfd, pidfd, fd, 0);
	ck_assert_msg(notifier >= 0, strerror(errno));
	return notifier;
}

static void check_target_result(long ret, int err)
{
	int buf;

	read(pipefd[0], &buf, 1);
	ck_assert_msg(at->ret == ret,
		      "expect return value %ld to be equal to %ld", at->ret,
		      ret);
	ck_assert_int_eq(at->err, err);
	ck_assert_int_eq(close(pipefd[0]), 0);
}

void setup()
{
	int ret;

	ck_assert_int_ne(pipe(pipefd), -1);
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pid_t pid = do_clone(target, NULL);
	ck_assert_int_ge(pid, 0);

	ck_assert_int_ne(close(pipefd[1]), -1);
	notifyfd = get_fd_notifier(pid);

	memset(&req, 0, sizeof(req));
	ret = ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_RECV, &req);
	ck_assert_msg(ret == 0, strerror(errno));
	ck_assert_msg((req.data).nr == nr, "filter syscall nr: %d",
		      (req.data).nr);
}

void teardown()
{
	if (at != NULL)
		munmap(at, sizeof(struct args_target));
}

START_TEST(test_act_continue)
{
	struct action actions[] = {
		{ .type = A_CONT },
	};
	int ret = do_actions(actions, sizeof(actions) / sizeof(actions[0]), -1,
			     notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	ck_assert_int_eq(at->err, 0);
}
END_TEST

START_TEST(test_act_block)
{
	struct action actions[] = {
		{
			.type = A_BLOCK,
			.block = { .error = -1 },
		},
	};
	int ret = do_actions(actions, sizeof(actions) / sizeof(actions[0]), -1,
			     notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(-1, 0);
}
END_TEST

START_TEST(test_act_return)
{
	struct action actions[] = {
		{
			.type = A_RETURN,
			.ret = { .value = 1 },
		},
	};
	int ret = do_actions(actions, sizeof(actions) / sizeof(actions[0]), -1,
			     notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0);
}
END_TEST

Suite *action_call_suite(void)
{
	Suite *s;
	TCase *tactions;

	s = suite_create("Perform actions");
	tactions = tcase_create("actions");

	tcase_add_checked_fixture(tactions, setup, teardown);
	tcase_set_timeout(tactions, 30);
	tcase_add_test(tactions, test_act_return);
	tcase_add_test(tactions, test_act_block);
	tcase_add_test(tactions, test_act_continue);

	suite_add_tcase(s, tactions);

	return s;
}

int main(void)
{
	int no_failed = 0;
	Suite *s;
	SRunner *runner;

	s = action_call_suite();
	runner = srunner_create(s);

	srunner_run_all(runner, CK_VERBOSE);
	no_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

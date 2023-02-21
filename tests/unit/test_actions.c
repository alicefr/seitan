#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
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

#include <check.h>

#include "../../gluten.h"
#include "../../actions.h"
#include "../../common.h"

struct args_target {
	long ret;
	int err;
	bool check_fd;
	int fd;
};

struct seccomp_notif req;
int notifyfd;
struct args_target *at;
int pipefd[2];
int nr = __NR_getpid;
pid_t pid;

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

static int create_test_fd()
{
	return open("/tmp", O_RDWR| O_TMPFILE );
}

static int target()
{
	int buf = 0;
	if (install_notification_filter() < 0) {
		return -1;
	}

	at->ret = getpid();
	at->err = errno;
	if (at->check_fd)
		read(pipefd[0], &buf, 1);

	close(pipefd[0]);

	write(pipefd[1], &buf, 1);
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

static void check_target_result(long ret, int err, bool ignore_ret)
{
	int buf;

	read(pipefd[0], &buf, 1);
	if (!ignore_ret)
		ck_assert_msg(at->ret == ret,
				"expect return value %ld to be equal to %ld",
				at->ret,
				ret);
	ck_assert_int_eq(at->err, err);
	ck_assert_int_eq(close(pipefd[0]), 0);
}

void target_exit()
{
	int status;

	waitpid(-1, &status, WUNTRACED | WNOHANG);
	if (WEXITSTATUS(status) != 0) {
		fprintf(stderr, "target process exited with an error\n");
		exit(-1);
	}
}

static bool has_fd(int pid, int fd)
{
        char path[PATH_MAX + 1];

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
	return access(path, F_OK) == 0;
}

static void check_target_fd(int pid, int fd)
{
	int buf = 0;

	ck_assert(has_fd(pid, fd));
	write(pipefd[1], &buf, 1);
	close(pipefd[1]);
}

void setup(bool check_fd)
{
	int ret;

	signal (SIGCHLD, target_exit);
	ck_assert_int_ne(pipe(pipefd), -1);
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at-> check_fd = check_fd;
	pid = do_clone(target, NULL);
	ck_assert_int_ge(pid, 0);

	/* Use write pipe to sync the target for checking the existance of the fd */
	if (!check_fd)
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

void setup_without_fd()
{
	setup(false);
}
void setup_fd()
{
	setup(true);
}

START_TEST(test_act_continue)
{
	struct action actions[] = {
		{ .type = A_CONT },
	};
	int ret = do_actions(NULL, actions, sizeof(actions) / sizeof(actions[0]), -1,
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
	int ret = do_actions(NULL, actions, sizeof(actions) / sizeof(actions[0]), -1,
			     notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(-1, 0, false);
}
END_TEST

START_TEST(test_act_return)
{
	struct action actions[] = {
		{
			.type = A_RETURN,
			.ret = { .type = IMMEDIATE, .value = 1 },
		},
	};
	int ret = do_actions(NULL, actions, sizeof(actions) / sizeof(actions[0]), -1,
			     notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0, false);
}
END_TEST

START_TEST(test_act_return_ref)
{
	int64_t v = 2;
	struct action actions[] = {
		{
			.type = A_RETURN,
			.ret = { .type = REFERENCE, .value_p = &v },
		},
	};
	int ret = do_actions(NULL, actions, sizeof(actions) / sizeof(actions[0]), -1,
			     notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(v, 0, false);
}
END_TEST

START_TEST(test_act_return_empty_ref)
{
	struct action actions[] = {
		{
			.type = A_RETURN,
			.ret = { .type = REFERENCE, .value_p = NULL },
		},
	};
	int ret = do_actions(NULL, actions, sizeof(actions) / sizeof(actions[0]), -1,
			     notifyfd, req.id);
	ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_act_call)
{
	struct action actions[] = {
		{
			.type = A_CALL,
			.call = { .nr = __NR_getppid, .has_ret = false },
		},
		{ .type = A_CONT },
	};
	int ret = do_actions(NULL, actions, sizeof(actions) / sizeof(actions[0]), -1,
			notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0, true);
}
END_TEST

static void test_inject(struct action actions[], int n)
{
	int fd_inj;
	int test_fd = 3;
	int ret;

	fd_inj = create_test_fd();
	ck_assert_int_ge(fd_inj,0);
	actions[0].inj.newfd = fd_inj;
	actions[0].inj.oldfd = test_fd;

	ret = do_actions(NULL, actions, n, -1, notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_fd(pid, test_fd);
}

START_TEST(test_act_inject_a)
{
	struct action actions[] = {{.type = A_INJECT_A}	};
	test_inject(actions, sizeof(actions) / sizeof(actions[0]));
}
END_TEST

START_TEST(test_act_inject)
{
	struct action actions[] = { { .type = A_INJECT }};
	test_inject(actions,sizeof(actions) / sizeof(actions[0]));
}
END_TEST

Suite *action_call_suite(void)
{
	Suite *s;
	int timeout = 30;
	TCase *cont, *block, *ret, *call;
	TCase *inject, *inject_a;

	s = suite_create("Perform actions");

	cont = tcase_create("a_continue");
	tcase_add_checked_fixture(cont, setup_without_fd, teardown);
	tcase_set_timeout(cont, timeout);
	tcase_add_test(cont, test_act_continue);
	suite_add_tcase(s, cont);

	ret = tcase_create("a_return");
	tcase_add_checked_fixture(ret, setup_without_fd, teardown);
	tcase_set_timeout(ret, timeout);
	tcase_add_test(ret, test_act_return);
	tcase_add_test(ret, test_act_return_ref);
	tcase_add_test(ret, test_act_return_empty_ref);
	suite_add_tcase(s, ret);

	block = tcase_create("a_block");
	tcase_add_checked_fixture(block, setup_without_fd, teardown);
	tcase_set_timeout(block, timeout);
	tcase_add_test(block, test_act_block);
	suite_add_tcase(s, block);

	call = tcase_create("a_call");
	tcase_add_checked_fixture(call, setup_without_fd, teardown);
	tcase_set_timeout(call, timeout);
	tcase_add_test(call, test_act_call);
	suite_add_tcase(s, call);

	inject = tcase_create("a_inject");
	tcase_add_checked_fixture(inject, setup_fd, teardown);
	tcase_set_timeout(inject, timeout);
	tcase_add_test(inject, test_act_inject);
	suite_add_tcase(s, inject);

	inject_a = tcase_create("a_inject_a");
	tcase_add_checked_fixture(inject_a, setup_fd, teardown);
	tcase_set_timeout(inject_a, timeout);
	tcase_add_test(inject_a, test_act_inject_a);
	suite_add_tcase(s, inject_a);

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

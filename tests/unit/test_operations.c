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
#include <sys/un.h>
#include <sys/socket.h>

#include <check.h>

#include "../../gluten.h"
#include "../../operations.h"
#include "../../common.h"

struct args_target {
	long ret;
	int err;
	bool check_fd;
	int fd;
	int nr;
	void *args[6];
};

struct seccomp_notif req;
int notifyfd;
struct args_target *at;
int pipefd[2];
pid_t pid;

uint16_t tmp_data[TMP_DATA_SIZE];

static int install_notification_filter(int nr)
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
	return open("/tmp", O_RDWR | O_TMPFILE);
}

static int target()
{
	int buf = 0;
	if (install_notification_filter(at->nr) < 0) {
		return -1;
	}

	at->ret = syscall(at->nr, at->args[0], at->args[1], at->args[2],
			  at->args[3], at->args[4], at->args[5]);
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
			      at->ret, ret);
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

void setup()
{
	int ret;

	signal(SIGCHLD, target_exit);
	ck_assert_int_ne(pipe(pipefd), -1);
	pid = do_clone(target, NULL);
	ck_assert_int_ge(pid, 0);

	/* Use write pipe to sync the target for checking the existance of the fd */
	if (!at->check_fd)
		ck_assert_int_ne(close(pipefd[1]), -1);

	notifyfd = get_fd_notifier(pid);

	memset(&req, 0, sizeof(req));
	ret = ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_RECV, &req);
	ck_assert_msg(ret == 0, strerror(errno));
	ck_assert_msg((req.data).nr == at->nr, "filter syscall nr: %d",
		      (req.data).nr);
}

void teardown()
{
	if (at != NULL)
		munmap(at, sizeof(struct args_target));
}

void setup_without_fd()
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_getpid;
	setup();
}
void setup_fd()
{
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = true;
	at->nr = __NR_getpid;
	setup();
}

void setup_target_connect()
{
	struct sockaddr_un addr;
	socklen_t len;
	int fd;

	len = sizeof(char) * 108;
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ck_assert_int_ge(fd, 0);
	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sun_path, "/tmp/test.sock");
	addr.sun_family = AF_UNIX;
	at = mmap(NULL, sizeof(struct args_target), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	at->check_fd = false;
	at->nr = __NR_connect;
	at->args[0] = (void *)(long)fd;
	at->args[1] = (void *)&addr;
	at->args[2] = (void *)(long)len;
	setup();
}

START_TEST(test_act_continue)
{
	struct op operations[] = {
		{ .type = OP_CONT },
	};
	int ret = do_operations(NULL, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	ck_assert_int_eq(at->err, 0);
}
END_TEST

START_TEST(test_act_block)
{
	struct op operations[] = {
		{
			.type = OP_BLOCK,
			.block = { .error = -1 },
		},
	};
	int ret = do_operations(NULL, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	/*
	 * The tests use getpid that returns the error with ret and it is always
	 * successful
	 */
	check_target_result(operations[0].block.error, 1, false);
}
END_TEST

START_TEST(test_act_return)
{
	struct op operations[] = {
		{
			.type = OP_RETURN,
			.ret = { .type = IMMEDIATE, .value = 1 },
		},
	};
	int ret = do_operations(NULL, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0, false);
}
END_TEST

START_TEST(test_act_return_ref)
{
	int64_t v = 2;
	uint16_t offset = 4;
	struct op operations[] = {
		{
			.type = OP_RETURN,
			.ret = { .type = REFERENCE, .value_off = offset },
		},
	};
	memcpy((uint16_t *)&tmp_data + offset, &v, sizeof(v));

	int ret = do_operations(&tmp_data, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(v, 0, false);
}
END_TEST

START_TEST(test_act_call)
{
	struct op operations[] = {
		{
			.type = OP_CALL,
			.call = { .nr = __NR_getppid, .has_ret = false },
		},
		{ .type = OP_CONT },
	};
	int ret = do_operations(NULL, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0, true);
}
END_TEST

START_TEST(test_act_call_ret)
{
	struct op operations[] = {
		{
			.type = OP_CALL,
			.call = { .nr = __NR_getppid,
				  .has_ret = true,
				  .ret_off = 2 },
		},
		{ .type = OP_CONT },
	};
	int ret = do_operations(&tmp_data, operations, &req,
			     sizeof(operations) / sizeof(operations[0]), -1, notifyfd,
			     req.id);
	long r;
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(1, 0, true);
	memcpy(&r, &tmp_data[2], sizeof(r));
	ck_assert_int_eq(r, getpid());
}
END_TEST

static void test_inject(struct op operations[], int n, bool reference)
{
	uint16_t new_off = 2, old_off = 4;
	int fd_inj;
	int test_fd = 3;
	int ret;

	fd_inj = create_test_fd();
	ck_assert_int_ge(fd_inj, 0);
	if (reference) {
		memcpy((uint16_t *)&tmp_data + new_off, &fd_inj,
		       sizeof(fd_inj));
		memcpy((uint16_t *)&tmp_data + old_off, &test_fd,
		       sizeof(test_fd));

		operations[0].inj.newfd.fd_off = new_off;
		operations[0].inj.newfd.type = REFERENCE;
		operations[0].inj.oldfd.fd_off = old_off;
		operations[0].inj.oldfd.type = REFERENCE;
	} else {
		operations[0].inj.newfd.fd = fd_inj;
		operations[0].inj.newfd.type = IMMEDIATE;
		operations[0].inj.oldfd.fd = test_fd;
		operations[0].inj.oldfd.type = IMMEDIATE;
	}

	ret = do_operations(&tmp_data, operations, &req,n, -1, notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_fd(pid, test_fd);
}

START_TEST(test_act_inject_a)
{
	struct op operations[] = { { .type = OP_INJECT_A } };
	test_inject(operations, sizeof(operations) / sizeof(operations[0]), false);
}
END_TEST

START_TEST(test_act_inject_a_ref)
{
	struct op operations[] = { { .type = OP_INJECT_A } };
	test_inject(operations, sizeof(operations) / sizeof(operations[0]), true);
}
END_TEST

START_TEST(test_act_inject)
{
	struct op operations[] = { { .type = OP_INJECT } };
	test_inject(operations, sizeof(operations) / sizeof(operations[0]), false);
}
END_TEST

START_TEST(test_act_inject_ref)
{
	struct op operations[] = { { .type = OP_INJECT } };
	test_inject(operations, sizeof(operations) / sizeof(operations[0]), true);
}
END_TEST

START_TEST(test_op_copy)
{
	struct op operations[] = {
		{ .type = OP_COPY_ARGS },
		{
			.type = OP_RETURN,
			.ret = { .type = IMMEDIATE, .value = 0 },
		},
	};
	struct op_copy_args *o = &operations[0].copy;
	struct sockaddr_un *addr;
	socklen_t *len, expect;
	int ret;

	o->args[0] = (struct copy_arg){ .args_off = 0,
					.type = IMMEDIATE,
					.size = sizeof(int) };
	o->args[1] =
		(struct copy_arg){ .args_off = sizeof(int) / sizeof(uint16_t),
				   .type = REFERENCE,
				   .size = sizeof(struct sockaddr_un) };
	o->args[2] = (struct copy_arg){ .args_off = o->args[1].args_off +
						    sizeof(struct sockaddr_un) /
							    sizeof(uint16_t),
					.type = IMMEDIATE,
					.size = sizeof(socklen_t) };
	ret = do_operations(&tmp_data, operations, &req,
			    sizeof(operations) / sizeof(operations[0]), -1,
			    notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(0, 0, false);
	addr = (struct sockaddr_un *)(tmp_data + o->args[1].args_off);
	ck_assert_str_eq(addr->sun_path, "/tmp/test.sock");
	ck_assert(addr->sun_family == AF_UNIX);
	expect = sizeof(addr->sun_path);
	len = (socklen_t *)(tmp_data + o->args[2].args_off);
	ck_assert_msg(*len == expect, "expect len %x to be equal to %x", *len,
		      expect);
}
END_TEST

START_TEST(test_op_cmp_eq)
{
	char s[30] = "Hello Test!!";
	struct op operations[] = {
		{ .type = OP_CMP,
		  .cmp = { .s1_off = 0,
			   .s2_off = sizeof(s) / sizeof(uint16_t),
			   .size = sizeof(s),
			   .jmp = 2 } },
		{ .type = OP_CONT },
		{ .type = OP_END },
		{ .type = OP_BLOCK, .block = { .error = -1 } },
	};
	int ret;

	memcpy((uint16_t *)&tmp_data + operations[0].cmp.s1_off, &s, sizeof(s));
	memcpy((uint16_t *)&tmp_data + operations[0].cmp.s2_off, &s, sizeof(s));

	ret = do_operations(&tmp_data, operations, &req,
			    sizeof(operations) / sizeof(operations[0]), -1,
			    notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	ck_assert_int_eq(at->err, 0);
}
END_TEST

START_TEST(test_op_cmp_neq)
{
	char s1[30] = "Hello Test!!";
	char s2[30] = "Hello World!!";
	struct op operations[] = {
		{ .type = OP_CMP,
		  .cmp = { .s1_off = 0,
			   .s2_off = sizeof(s1) / sizeof(uint16_t),
			   .size = sizeof(s1),
			   .jmp = 2 } },
		{ .type = OP_CONT },
		{ .type = OP_END },
		{ .type = OP_BLOCK, .block = { .error = -1 } },
	};
	int ret;

	memcpy((uint16_t *)&tmp_data + operations[0].cmp.s1_off, &s1,
	       sizeof(s1));
	memcpy((uint16_t *)&tmp_data + operations[0].cmp.s2_off, &s2,
	       sizeof(s2));

	ret = do_operations(&tmp_data, operations, &req,
			    sizeof(operations) / sizeof(operations[0]), -1,
			    notifyfd, req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	check_target_result(-1, 1, false);
}
END_TEST

Suite *op_call_suite(void)
{
	Suite *s;
	int timeout = 30;
	TCase *cont, *block, *ret, *call, *cmp;
	TCase *inject, *inject_a;
	TCase *copy;

	s = suite_create("Perform operations");

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
	tcase_add_test(call, test_act_call_ret);
	suite_add_tcase(s, call);

	inject = tcase_create("a_inject");
	tcase_add_checked_fixture(inject, setup_fd, teardown);
	tcase_set_timeout(inject, timeout);
	tcase_add_test(inject, test_act_inject);
	tcase_add_test(inject, test_act_inject_ref);
	suite_add_tcase(s, inject);

	inject_a = tcase_create("a_inject_a");
	tcase_add_checked_fixture(inject_a, setup_fd, teardown);
	tcase_set_timeout(inject_a, timeout);
	tcase_add_test(inject_a, test_act_inject_a);
	tcase_add_test(inject_a, test_act_inject_a_ref);
	suite_add_tcase(s, inject_a);

	copy = tcase_create("op_copy");
	tcase_add_checked_fixture(copy, setup_target_connect, teardown);
	tcase_set_timeout(copy, 120);
	tcase_add_test(copy, test_op_copy);
	suite_add_tcase(s, copy);

	cmp = tcase_create("op_cmp");
	tcase_add_checked_fixture(cmp, setup_without_fd, teardown);
	tcase_set_timeout(cmp, timeout);
	tcase_add_test(cmp, test_op_cmp_eq);
	tcase_add_test(cmp, test_op_cmp_neq);
	suite_add_tcase(s, cmp);

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

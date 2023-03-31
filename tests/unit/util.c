#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
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

#include "testutil.h"
#include "common.h"
#include "filter.h"

struct seccomp_notif req;
int notifyfd;
struct args_target *at;
int pipefd[2];
pid_t pid;
char path[] = "/tmp/test-seitan";
uint16_t tmp_data[TMP_DATA_SIZE];

int install_notification_filter(struct args_target *at)
{
	/* filter a single syscall for the tests */
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, at->nr, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
	};
	return install_filter(
		filter, (unsigned short)(sizeof(filter) / sizeof(filter[0])));
}

int target()
{
        int buf = 0;
	if (at->install_filter(at) < 0) {
		return -1;
	}

	at->ret = syscall(at->nr, at->args[0], at->args[1], at->args[2],
                          at->args[3], at->args[4], at->args[5]);
        at->err = errno;
        if (at->open_path) {
                if ((at->fd = open(path, O_CREAT | O_RDONLY)) < 0) {
                        perror("open");
                        return -1;
                }
        }
        if (at->check_fd)
                read(pipefd[0], &buf, 1);

        close(pipefd[0]);

        write(pipefd[1], &buf, 1);
        close(pipefd[1]);
        exit(0);
}

pid_t do_clone(int (*fn)(void *), void *arg)
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

int create_test_fd()
{
	return open("/tmp", O_RDWR | O_TMPFILE);
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

void target_exit()
{
	int status;

	waitpid(-1, &status, WUNTRACED | WNOHANG);
	if (WEXITSTATUS(status) != 0) {
		fprintf(stderr, "target process exited with an error\n");
		exit(-1);
	}
}

void check_target_fd(int pid, int fd)
{
	int buf = 0;

	ck_assert(has_fd(pid, fd));
	write(pipefd[1], &buf, 1);
	close(pipefd[1]);
}

bool has_fd(int pid, int fd)
{
	char path[PATH_MAX + 1];

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
	return access(path, F_OK) == 0;
}

void check_target_result(long ret, int err, bool ignore_ret)
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

void continue_target()
{
	struct seccomp_notif_resp resp;
	int ret;

	ret = ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id);
	ck_assert_msg(ret == 0, strerror(errno));
	resp.id = req.id;
	resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	resp.error = 0;
	resp.val = 0;
	ret = ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
	ck_assert_msg(ret == 0, strerror(errno));
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

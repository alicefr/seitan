#ifndef TESTUTIL_H
#define TESTUTIL_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

#include <check.h>

#define STACK_SIZE (1024 * 1024 / 8)

struct args_target {
        long ret;
        int err;
        bool check_fd;
        bool open_path;
        int fd;
        int nr;
	void *args[6];
	int (*install_filter)(struct args_target *at);
};

extern struct seccomp_notif req;
extern int notifyfd;
extern struct args_target *at;
extern int pipefd[2];
extern pid_t pid;
extern char path[100];

extern uint16_t tmp_data[TMP_DATA_SIZE];

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

#endif /* TESTUTIL_H */

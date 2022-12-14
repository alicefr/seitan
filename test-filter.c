#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define SIZE_FILTER 1024

extern char **environ;

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
        return syscall(__NR_seccomp, operation, flags, args);
}

int main(int argc, char **argv)
{
        struct sock_filter filter[SIZE_FILTER];
        struct sock_fprog prog;
        size_t n, fd;
	char *binary, **args;
	int ret;

        (void)argc;

        if (argc < 2) {
                perror("missing input file");
                exit(EXIT_FAILURE);
        }
	binary = argv[2];
	args = &argv[3];
        fd = open(argv[1], O_CLOEXEC | O_RDONLY);

	n = read(fd, filter, sizeof(struct sock_filter)*SIZE_FILTER);
        close(fd);

        prog.filter = filter;
        prog.len = n/sizeof(struct sock_filter);
        ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (ret < 0) {
		perror("fail prctl");
		exit(EXIT_FAILURE);
	}
	ret = seccomp(SECCOMP_SET_MODE_FILTER,
			SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (ret < 0) {
		perror("fail setting filter");
	}

	execvpe(binary, args, environ);
	if (errno != ENOENT) {
		fprintf(stderr, "execvpe with %s\n", binary);
	}

        perror("execvpe");

	return 0;
}

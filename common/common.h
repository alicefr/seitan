#ifndef COMMON_H_
#define COMMON_H_

#include <linux/filter.h>

int find_fd_seccomp_notifier(const char *pid);
int install_filter(struct sock_filter *filter, unsigned short len);
#endif

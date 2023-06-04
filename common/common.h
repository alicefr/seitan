/* SPDX-License-Identifier: GPL-2.0-or-later
* Copyright 2023 Red Hat GmbH
* Authors: Alice Frosi <afrosi@redhat.com>
*	   Stefano Brivio <sbrivio@redhat.com>
*/

#ifndef COMMON_H_
#define COMMON_H_

#include <linux/filter.h>

int find_fd_seccomp_notifier(const char *pid);
int install_filter(struct sock_filter *filter, unsigned short len);
#endif

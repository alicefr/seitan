/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#ifndef DISASM_H_
#define DISASM_H_

#define SIZE_FILTER 1024

void bpf_disasm(const struct sock_filter f, unsigned int i);
void bpf_disasm_all(const struct sock_filter *f, unsigned int len);

#endif

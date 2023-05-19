/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#ifndef FILTER_H_
#define FILTER_H_

#include <stdint.h>

#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <stdbool.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ENDIAN(_lo, _hi) _lo, _hi
#define LO_ARG(idx) offsetof(struct seccomp_data, args[(idx)])
#define HI_ARG(idx) offsetof(struct seccomp_data, args[(idx)]) + sizeof(__u32)
#define get_hi(x) ((uint32_t)((x) >> 32))
#define get_lo(x) ((uint32_t)((x)&0xffffffff))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ENDIAN(_lo, _hi) _hi, _lo
#define LO_ARG(idx) offsetof(struct seccomp_data, args[(idx)]) + sizeof(__u32)
#define HI_ARG(idx) offsetof(struct seccomp_data, args[(idx)])
#define get_lo(x) ((uint32_t)((x) >> 32))
#define get_hi(x) ((uint32_t)((x)&0xffffffff))
#else
#error "Unknown endianness"
#endif

#define JGE(nr, right, left) \
	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (nr), (right), (left))
#define JUMPA(jump) BPF_JUMP(BPF_JMP | BPF_JA, (jump), 0, 0)
#define EQ(x, a1, a2) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (x), (a1), (a2))
#define NEQ(x, a1, a2) EQ((x), (a2), (a1))
#define GT(x, a1, a2) BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, (x), (a1), (a2))
#define GE(x, a1, a2) BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, (x), (a1), (a2))
#define LT(x, a1, a2) GE((x), (a2), (a1))
#define LE(x, a1, a2) GT((x), (a2), (a1))
#define LOAD(x) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (x))
#define AND(x) BPF_STMT(BPF_ALU | BPF_AND | BPF_IMM, (x))
#define MAX_FILTER 1024

#define MAX_JUMPS 128
#define EMPTY -1

#define N_SYSCALL 512
#define MAX_ENTRIES_SYSCALL 16
#define MAX_ENTRIES N_SYSCALL * MAX_ENTRIES_SYSCALL

enum bpf_type { BPF_U32, BPF_U64 };

union bpf_value {
	uint32_t v32;
	uint64_t v64;
};

enum bpf_cmp { NO_CHECK = 0, EQ, NE, LE, LT, GE, GT, AND_EQ, AND_NE };

struct bpf_arg {
	union bpf_value value;
	enum bpf_type type;
	enum bpf_cmp cmp;
	union bpf_value op2;
};

struct bpf_entry {
	struct bpf_arg args[6];
};

void filter_notify(long nr);
void filter_needs_deref(void);
void filter_add_arg(int index, struct bpf_arg arg);
void filter_write(const char *path);
void filter_flush_args();

#endif

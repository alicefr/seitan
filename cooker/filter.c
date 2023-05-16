
/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "filter.h"
#include "common/util.h"

struct bpf_entry entries[MAX_ENTRIES];
static unsigned int index_entries = 0;

/**
 * struct filter_call_input - First input stage for cooker notification requests
 * @notify:	Notify on this system call
 * @count:	How many entry for the same syscall
 * @entries:	Index for the arguments for every entry
 */
struct filter_call_input {
	bool notify;
	unsigned int count;
	int entries[MAX_ENTRIES_SYSCALL];
} filter_input[N_SYSCALL] = { 0 };

static long current_nr;

static void set_no_args(struct bpf_entry *entry)
{
	entry->args[0].cmp = NO_CHECK;
	entry->args[1].cmp = NO_CHECK;
	entry->args[2].cmp = NO_CHECK;
	entry->args[3].cmp = NO_CHECK;
	entry->args[4].cmp = NO_CHECK;
	entry->args[5].cmp = NO_CHECK;
}

static unsigned int get_number_entries(long nr)
{
	struct filter_call_input *call = filter_input + nr;

	return call->count;
}

static bool need_check_arg(const struct bpf_entry *entry)
{
	return  entry->args[0].cmp != NO_CHECK ||
		entry->args[1].cmp != NO_CHECK ||
		entry->args[2].cmp != NO_CHECK ||
		entry->args[3].cmp != NO_CHECK ||
		entry->args[4].cmp != NO_CHECK ||
		entry->args[5].cmp != NO_CHECK;
}

static bool has_args(long nr)
{
	struct filter_call_input *call = filter_input + nr;

	if (call-> count < 1)
		return false;

	/* Check if the first entry has some arguments */
	return need_check_arg(&entries[call->entries[0]]);
}

static unsigned get_args_for_entry(const struct bpf_entry *entry)
{
	unsigned i, n = 0;

	for (i = 0; i < 6; i++)
		if (entry->args[i].cmp != NO_CHECK)
			n++;
	return n;
}

/* Calculate how many instruction for the syscall */
static unsigned int get_n_args_syscall_instr(long nr)
{
	struct filter_call_input *call = filter_input + nr;
	const struct bpf_entry *entry;
	unsigned int n = 0, total_instr = 0;
	unsigned int i, k;

	for (i = 0; i < call->count; i++) {
		entry = &entries[call->entries[i]];
		n = 0;
		for (k = 0; k < 6; k++) {
			if (entry->args[k].cmp == NO_CHECK)
				continue;
			switch (entry->args[k].type) {
			case BPF_U32:
				/* For 32 bit arguments
				 * comparison instructions (2):
				 *   1 loading the value + 1 for evaluation
				 * arithemtic instructions (3):
				 *   1 loading the value + 1 for the operation + 1 for evaluation
				 */
				if (entry->args[k].cmp == AND_EQ ||
				    entry->args[k].cmp == AND_NE)
					n += 3;
				else
					n += 2;
				break;
			case BPF_U64:
				/* For 64 bit arguments: 32 instructions * 2
				 * for loading and evaluating the high and low 32 bits chuncks.
				*/
				if (entry->args[k].cmp == AND_EQ ||
				    entry->args[k].cmp == AND_NE)
					n += 6;
				else
					n += 4;
				break;
			}
		}
		total_instr += n;
		/* If there at least an argument, then there is the jump to the
		 * notification */
		if (n > 0)
			total_instr++;
	}
	/* If there at least an argument for that syscall, then there is the jump to the
	* accept */
	if (has_args(nr))
		total_instr++;

	return total_instr;
}

/**
 * filter_notify() - Start of notification request, check/flush previous one
 * @nr:		System call number, -1 to just flush previous request
 */
void filter_notify(long nr) {
	struct filter_call_input *call = filter_input + nr;

	if (nr >= 0) {
		current_nr = nr;
		call->notify = true;
	}
}

/**
 * Use temporary filter_call_cur_args storage. When there's a new notification,
 * or the parser is done, we flush these argument matches to filter_input, and
 * check if they match (including no-matches) all the previous argument
 * specification. If they don't, the arguments can't be evaluated in the filter.
 */
void filter_add_arg(int index, struct bpf_arg arg)
{
	struct filter_call_input *call = filter_input + current_nr;

	/* If it reaches the maximum number of entries per syscall, then we simply
	 * notify for all the arguments and ignore the other arguments.
	 */
	if (call->count >= MAX_ENTRIES_SYSCALL) {
		set_no_args(&entries[call->entries[0]]);
		return;
	}
	call->entries[call->count++] = index_entries;
	memcpy(&entries[++index_entries].args[index], &arg, sizeof(arg));
}

void filter_needs_deref(void)
{
	struct filter_call_input *call = filter_input + current_nr;

	call->count = MAX_ENTRIES_SYSCALL;
	set_no_args(&entries[call->entries[0]]);
}

static int table[N_SYSCALL];

static unsigned int create_table_syscall()
{
	unsigned int i, count = 0;

	for (i = 0; i < N_SYSCALL; i++)
		if (filter_input[i].notify)
			table[count++] = i;
	return count;
}

static long get_syscall(unsigned int i)
{
	return (long)table[i];
}


static unsigned int count_shift_right(unsigned int n)
{
	unsigned int i = 0;
	for (; n > 0; i++) {
		n = n >> 1;
	}
	return i;
}

static void insert_pair(int jumps[], int arr[], unsigned int level)
{
	unsigned int i_a, i;
	for (i = 0; i < level; i++) {
		i_a = 2 * i + 1;
		if (arr[i_a] == EMPTY) {
			jumps[i] = arr[i_a - 1];
		} else {
			jumps[i] = arr[i_a];
		}
	}
}

static unsigned int left_child(unsigned int parent_index)
{
	unsigned int level = count_shift_right(parent_index + 1);
	/* 2^(level) -1 gives the beginning of the next interval */
	unsigned int next_interval = (1 << level) - 1;
	/* 2^(level -1) -1  gives the beginning of the current interval */
	unsigned begin = (1 << (level - 1)) - 1;
	unsigned i = parent_index - begin;
	return next_interval + 2 * i;
}

static unsigned int right_child(unsigned int parent_index)
{
	return left_child(parent_index) + 1;
}

static void create_lookup_nodes(int jumps[], unsigned int n)
{
	unsigned int i, index;
	unsigned int old_interval, interval;

	for (i = 0; i < MAX_JUMPS; i++)
		jumps[i] = EMPTY;

	if (n < 2) {
		jumps[0] = 0;
		return;
	}
	old_interval = 1 << count_shift_right(n - 1);
	interval = old_interval >> 1;

	/* first scan populate the last level of jumps */
	for (i = interval - 1, index = 1; index < old_interval && index < n;
	     i++, index += 2) {
		jumps[i] = index;
	}
	if (n % 2 == 1) {
		jumps[i] = index - 1;
	}
	for (old_interval = interval, interval = interval / 2; interval > 0;
	     old_interval = interval, interval = interval / 2) {
		insert_pair(&jumps[interval - 1], &jumps[old_interval - 1],
			    interval);
	}
}

static unsigned int eq(struct sock_filter filter[], int idx,
		       const struct bpf_entry *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (entry->args[idx].type) {
	case BPF_U64:
		hi = get_hi((entry->args[idx]).value.v64);
		lo = get_lo((entry->args[idx]).value.v64);
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)EQ(lo, 0, jfalse);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)EQ(hi, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)EQ(
			entry->args[idx].value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int gt(struct sock_filter filter[], int idx,
		       const struct bpf_entry *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (entry->args[idx].type) {
	case BPF_U64:
		hi = get_hi((entry->args[idx]).value.v64);
		lo = get_lo((entry->args[idx]).value.v64);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)GT(hi, jtrue + 2, 0);
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)GT(lo, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)GT(
			entry->args[idx].value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int lt(struct sock_filter filter[], int idx,
		       const struct bpf_entry *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (entry->args[idx].type) {
	case BPF_U64:
		hi = get_hi((entry->args[idx]).value.v64);
		lo = get_lo((entry->args[idx]).value.v64);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)LT(hi, jtrue + 2, jfalse);
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)LT(lo, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)LT(
			entry->args[idx].value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int neq(struct sock_filter filter[], int idx,
			const struct bpf_entry *entry, unsigned int jtrue,
			unsigned int jfalse)
{
	return eq(filter, idx, entry, jfalse, jtrue);
}

static unsigned int ge(struct sock_filter filter[], int idx,
		       const struct bpf_entry *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	return lt(filter, idx, entry, jfalse, jtrue);
}

static unsigned int le(struct sock_filter filter[], int idx,
		       const struct bpf_entry *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	return gt(filter, idx, entry, jfalse, jtrue);
}

static unsigned int and_eq (struct sock_filter filter[], int idx,
			    const struct bpf_entry *entry, unsigned int jtrue,
			    unsigned int jfalse)
{
	unsigned int size = 0;

	switch (entry->args[idx].type) {
	case BPF_U64:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)AND(
			get_lo(entry->args[idx].op2.v64));
		filter[size++] = (struct sock_filter)EQ(
			get_lo((entry->args[idx]).value.v64), 0, jfalse);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)AND(
			get_hi(entry->args[idx].op2.v64));
		filter[size++] = (struct sock_filter)EQ(
			get_hi(entry->args[idx].value.v64), jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] =
			(struct sock_filter)AND(entry->args[idx].op2.v32);
		filter[size++] = (struct sock_filter)EQ(
			entry->args[idx].value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int and_ne(struct sock_filter filter[], int idx,
			   const struct bpf_entry *entry, unsigned int jtrue,
			   unsigned int jfalse)
{
	unsigned int size = 0;

	switch (entry->args[idx].type) {
	case BPF_U64:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)AND(
			get_lo(entry->args[idx].op2.v64));
		filter[size++] = (struct sock_filter)EQ(
			get_lo((entry->args[idx]).value.v64), 0, jtrue + 3);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)AND(
			get_hi(entry->args[idx].op2.v64));
		filter[size++] = (struct sock_filter)EQ(
			get_hi(entry->args[idx].value.v64), jfalse, jtrue);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] =
			(struct sock_filter)AND(entry->args[idx].op2.v32);
		filter[size++] = (struct sock_filter)EQ(
			entry->args[idx].value.v32, jfalse, jtrue);
		break;
	}

	return size;
}

static unsigned int insert_args(struct sock_filter filter[], long nr)
{
	struct filter_call_input *call = filter_input + nr;
	unsigned int i, k, size, next_offset, n_checks = 0;
	unsigned int count = get_number_entries(nr);
	struct bpf_entry *entry;
	unsigned int offset = 0;

	for (i = 0; i < count; i++) {
		n_checks = 0;
		entry = &entries[call->entries[i]];
		next_offset = get_args_for_entry(entry);
		for (; k < 6; k++) {
			offset = next_offset - n_checks;
			switch (entry->args[k].cmp) {
			case NO_CHECK:
				continue;
			case EQ:
				size += eq(&filter[size], k, entry, 0, offset);
				break;
			case NE:
				size += neq(&filter[size], k, entry, 0, offset);
				break;
			case GT:
				size += gt(&filter[size], k, entry, 0, offset);
				break;
			case LT:
				size += lt(&filter[size], k, entry, 0, offset);
				break;
			case GE:
				size += ge(&filter[size], k, entry, 0, offset);
				break;
			case LE:
				size += le(&filter[size], k, entry, 0, offset);
				break;
			case AND_EQ:
				size += and_eq
					(&filter[size], k, entry, 0, offset);
				break;
			case AND_NE:
				size += and_ne(&filter[size], k, entry, 0,
					       offset);

				break;
			}
			n_checks++;
		}
		if (n_checks > 0)
			filter[size++] = (struct sock_filter)BPF_STMT(
				BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
	}

	return size;
}

unsigned int filter_build(struct sock_filter filter[],  unsigned n)
{
	unsigned int offset_left, offset_right;
	unsigned int n_nodes, notify, accept;
	unsigned int next_offset, offset;
	unsigned int size = 0;
	int nodes[MAX_JUMPS];
	unsigned int i;
	long nr;

	create_lookup_nodes(nodes, n);

	/* No nodes if there is a single syscall */
	n_nodes = (1 << count_shift_right(n - 1)) - 1;

	/* Pre */
	/* cppcheck-suppress badBitmaskCheck */
	filter[size++] = (struct sock_filter)BPF_STMT(
		BPF_LD | BPF_W | BPF_ABS,
		(offsetof(struct seccomp_data, arch)));
	filter[size++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						      SEITAN_AUDIT_ARCH, 1, 0);
	filter[size++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						      SECCOMP_RET_ALLOW);
	/* cppcheck-suppress badBitmaskCheck */
	filter[size++] = (struct sock_filter)BPF_STMT(
		BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)));

	/* pre-check instruction + load syscall number (4 instructions) */
	accept = size + n_nodes + n;
	notify = accept + 1;

	/* Insert nodes */
	for (i = 0; i < n_nodes; i++) {
		if (nodes[i] == EMPTY) {
			filter[size++] =
				(struct sock_filter)JUMPA(accept - size);
		} else {
			nr = get_syscall(i);
			offset_left = left_child(i) - i - 1;
			offset_right = right_child(i) - i - 1;
			filter[size++] = (struct sock_filter)JGE(
				get_syscall(i), offset_right, offset_left);
		}
	}

	next_offset = n + 1;
	/* Insert leaves */
	for (i = 0; i < n; i++) {
		nr = get_syscall(i);
		if (get_number_entries(nr) > 0)
			offset = next_offset;
		else
		/* If the syscall doesn't have any arguments, then notify */
			offset = notify - size - 1;
		filter[size++] = (struct sock_filter)EQ(nr,
							offset,
							accept - size);
		next_offset += get_n_args_syscall_instr(nr) - 1;
	}
	/* Seccomp accept and notify instruction */
	filter[size++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						      SECCOMP_RET_ALLOW);
	filter[size++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						      SECCOMP_RET_USER_NOTIF);

	/*
	 * Insert args. It sequentially checks all the arguments for a syscall
	 * entry. If a check on the argument isn't equal then it jumps to
	 * check the following entry of the syscall and its arguments.
	 */
	for (i = 0; i < n; i++) {
		nr = get_syscall(i);
		size += insert_args(&filter[size], nr);
		if (has_args(nr))
			filter[size++] = (struct sock_filter)BPF_STMT(
				BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	}

	return size;
}

void filter_write(const char *path)
{
	struct sock_filter filter[MAX_FILTER];
	int fd, n;

	n = create_table_syscall();
	n = filter_build(filter, n);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  S_IRUSR | S_IWUSR);
	write(fd, filter, sizeof(struct sock_filter) * n);
	close(fd);
}

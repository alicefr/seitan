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
#include "util.h"

struct notify {
	long nr;
	struct bpf_arg arg[6];
} notify_call[512];

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

unsigned int left_child(unsigned int parent_index)
{
	unsigned int level = count_shift_right(parent_index + 1);
	/* 2^(level) -1 gives the beginning of the next interval */
	unsigned int next_interval = (1 << level) - 1;
	/* 2^(level -1) -1  gives the beginning of the current interval */
	unsigned begin = (1 << (level - 1)) - 1;
	unsigned i = parent_index - begin;
	return next_interval + 2 * i;
}

unsigned int right_child(unsigned int parent_index)
{
	return left_child(parent_index) + 1;
}

void create_lookup_nodes(int jumps[], unsigned int n)
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

static unsigned get_n_args_syscall_entry(const struct notify *entry)
{
	unsigned i, n = 0;

	for (i = 0; i < 6; i++)
		if (entry->arg[i].cmp != NO_CHECK)
			n++;
	return n;
}

static unsigned int get_n_args_syscall_instr(const struct notify *table,
					     int len)
{
	const struct notify *entry;
	bool has_arg = false;
	unsigned n = 0, total_instr = 0;
	int i;

	for (i = 0; i < len; i++) {
		entry = table + i;
		n = 0;
		for (unsigned int k = 0; k < 6; k++) {
			if (entry->arg[k].cmp == NO_CHECK)
				continue;
			switch (entry->arg[k].type) {
			case BPF_U32:
				/* For 32 bit arguments
				 * comparison instructions (2):
				 *   1 loading the value + 1 for evaluation
				 * arithemtic instructions (3):
				 *   1 loading the value + 1 for the operation + 1 for evaluation
				 */
				if (entry->arg[k].cmp == AND_EQ ||
				    entry->arg[k].cmp == AND_NE)
					n += 3;
				else
					n += 2;
				break;
			case BPF_U64:
				/* For 64 bit arguments: 32 instructions * 2
				 * for loading and evaluating the high and low 32 bits chuncks.
				*/
				if (entry->arg[k].cmp == AND_EQ ||
				    entry->arg[k].cmp == AND_NE)
					n += 6;
				else
					n += 4;
				break;
			}
		}
		total_instr += n;
		/* If there at least an argument, then there is the jump to the
		 * notification */
		if (n > 0) {
			has_arg = true;
			total_instr++;
		}
	}
	/* If there at least an argument for that syscall, then there is the jump to the
	* accept */
	if (has_arg)
		total_instr++;

	return total_instr;
}

static bool check_args_syscall_entry(const struct notify *entry){
	return entry->arg[0].cmp != NO_CHECK ||
	       entry->arg[1].cmp != NO_CHECK ||
	       entry->arg[2].cmp != NO_CHECK ||
	       entry->arg[3].cmp != NO_CHECK ||
	       entry->arg[4].cmp != NO_CHECK || entry->arg[5].cmp != NO_CHECK;
}

static unsigned int eq(struct sock_filter filter[], int idx,
		       const struct notify *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (entry->arg[idx].type) {
	case BPF_U64:
		hi = get_hi((entry->arg[idx]).value.v64);
		lo = get_lo((entry->arg[idx]).value.v64);
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)EQ(lo, 0, jfalse);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)EQ(hi, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)EQ(
			entry->arg[idx].value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int gt(struct sock_filter filter[], int idx,
		       const struct notify *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (entry->arg[idx].type) {
	case BPF_U64:
		hi = get_hi((entry->arg[idx]).value.v64);
		lo = get_lo((entry->arg[idx]).value.v64);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)GT(hi, jtrue + 2, 0);
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)GT(lo, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)GT(
			entry->arg[idx].value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int lt(struct sock_filter filter[], int idx,
		       const struct notify *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (entry->arg[idx].type) {
	case BPF_U64:
		hi = get_hi((entry->arg[idx]).value.v64);
		lo = get_lo((entry->arg[idx]).value.v64);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)LT(hi, jtrue + 2, jfalse);
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)LT(lo, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)LT(
			entry->arg[idx].value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int neq(struct sock_filter filter[], int idx,
			const struct notify *entry, unsigned int jtrue,
			unsigned int jfalse)
{
	return eq(filter, idx, entry, jfalse, jtrue);
}

static unsigned int ge(struct sock_filter filter[], int idx,
		       const struct notify *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	return lt(filter, idx, entry, jfalse, jtrue);
}

static unsigned int le(struct sock_filter filter[], int idx,
		       const struct notify *entry, unsigned int jtrue,
		       unsigned int jfalse)
{
	return gt(filter, idx, entry, jfalse, jtrue);
}

static unsigned int and_eq (struct sock_filter filter[], int idx,
			    const struct notify *entry, unsigned int jtrue,
			    unsigned int jfalse)
{
	unsigned int size = 0;

	switch (entry->arg[idx].type) {
	case BPF_U64:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)AND(
			get_lo(entry->arg[idx].op2.v64));
		filter[size++] = (struct sock_filter)EQ(
			get_lo((entry->arg[idx]).value.v64), 0, jfalse);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)AND(
			get_hi(entry->arg[idx].op2.v64));
		filter[size++] = (struct sock_filter)EQ(
			get_hi(entry->arg[idx].value.v64), jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] =
			(struct sock_filter)AND(entry->arg[idx].op2.v32);
		filter[size++] = (struct sock_filter)EQ(
			entry->arg[idx].value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int and_ne(struct sock_filter filter[], int idx,
			   const struct notify *entry, unsigned int jtrue,
			   unsigned int jfalse)
{
	unsigned int size = 0;

	switch (entry->arg[idx].type) {
	case BPF_U64:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] = (struct sock_filter)AND(
			get_lo(entry->arg[idx].op2.v64));
		filter[size++] = (struct sock_filter)EQ(
			get_lo((entry->arg[idx]).value.v64), 0, jtrue + 3);
		filter[size++] = (struct sock_filter)LOAD(HI_ARG(idx));
		filter[size++] = (struct sock_filter)AND(
			get_hi(entry->arg[idx].op2.v64));
		filter[size++] = (struct sock_filter)EQ(
			get_hi(entry->arg[idx].value.v64), jfalse, jtrue);
		break;
	case BPF_U32:
		filter[size++] = (struct sock_filter)LOAD(LO_ARG(idx));
		filter[size++] =
			(struct sock_filter)AND(entry->arg[idx].op2.v32);
		filter[size++] = (struct sock_filter)EQ(
			entry->arg[idx].value.v32, jfalse, jtrue);
		break;
	}

	return size;
}

unsigned int filter_build(struct sock_filter filter[], unsigned int n)
{
	unsigned int offset_left, offset_right;
	unsigned int n_nodes, notify, accept;
	unsigned int next_offset, offset;
	const struct notify *entry;
	unsigned int size = 0;
	unsigned int next_args_off;
	int nodes[MAX_JUMPS];
	unsigned int i, j, k;
	unsigned n_checks;

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
			offset_left = left_child(i) - i - 1;
			offset_right = right_child(i) - i - 1;
			filter[size++] = (struct sock_filter)JGE(
				notify_call[i].nr, offset_right, offset_left);
		}
	}

	next_offset = n + 1;
	/* Insert leaves */
	for (i = 0; i < n; i++) {
		/* If the syscall doesn't have any arguments, then notify */
		if (check_args_syscall_entry(notify_call + i))
			offset = next_offset;
		else
			offset = notify - size - 1;
		filter[size++] = (struct sock_filter)EQ(notify_call[i].nr,
							offset,
							accept - size);
		next_offset += get_n_args_syscall_instr(notify_call + i, n) - 1;
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
		bool has_arg = false;
		unsigned int count = 0, x;

		for (x = 0; x < 6; x++)
			count += notify_call[i].arg[x].cmp == NO_CHECK;

		for (j = 0; j < count; j++) {
			n_checks = 0;
			entry = notify_call + i + j;
			next_args_off = get_n_args_syscall_entry(entry);
			for (k = 0; k < 6; k++) {
				offset = next_args_off - n_checks;
				switch (entry->arg[k].cmp) {
				case NO_CHECK:
					continue;
				case EQ:
					size += eq(&filter[size], k, entry, 0,
						   offset);
					break;
				case NE:
					size += neq(&filter[size], k, entry, 0,
						    offset);
					break;
				case GT:
					size += gt(&filter[size], k, entry, 0,
						   offset);
					break;
				case LT:
					size += lt(&filter[size], k, entry, 0,
						   offset);
					break;
				case GE:
					size += ge(&filter[size], k, entry, 0,
						   offset);
					break;
				case LE:
					size += le(&filter[size], k, entry, 0,
						   offset);
					break;
				case AND_EQ:
					size += and_eq (&filter[size], k, entry,
							0, offset);
					break;
				case AND_NE:
					size += and_ne(&filter[size], k, entry,
						       0, offset);

					break;
				}
				n_checks++;
				has_arg = true;
			}
			if (check_args_syscall_entry(notify_call + i))
				filter[size++] = (struct sock_filter)BPF_STMT(
					BPF_RET | BPF_K,
					SECCOMP_RET_USER_NOTIF);
		}
		/* At this point none of the checks was positive, it jumps to
		 * the default behavior
		 */
		if (has_arg)
			filter[size++] = (struct sock_filter)BPF_STMT(
				BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	}

	return size;
}

/**
 * struct filter_call_input - First input stage for cooker notification requests
 * @notify:	Notify on this system call
 * @no_args:	No argument comparisons are allowed for this call
 * @args_set:	Argument matches were already set up once for this call
 * @arg:	Argument specification
 */
struct filter_call_input {
	bool notify;
	bool no_args;
	bool args_set;
	struct bpf_arg arg[6];
} filter_input[512] = { 0 };

static struct {
	bool used;
	struct bpf_arg arg[6];
} filter_current_args;

static long current_nr;

/**
 * filter_notify() - Start of notification request, check/flush previous one
 * @nr:		System call number, -1 to just flush previous request
 */
void filter_notify(long nr) {
	struct filter_call_input *call = filter_input + nr;
	long prev_nr = current_nr;

	if (nr >= 0) {
		current_nr = nr;
		call->notify = true;
	}

	if (filter_current_args.used) {
		struct filter_call_input *prev_call = filter_input + prev_nr;

		/* First time arguments for previous call are flushed? */
		if (!prev_call->args_set && !prev_call->no_args) {
			prev_call->args_set = true;
			memcpy(prev_call->arg, filter_current_args.arg,
			       sizeof(filter_current_args.arg));
			return;
		}

		prev_call->args_set = true;

		/* ...not the first time: check exact overlap of matches */
		if (memcmp(prev_call->arg, filter_current_args.arg,
			   sizeof(filter_current_args.arg)))
			prev_call->no_args = true;

		/* Flush temporary set of arguments */
		memset(&filter_current_args, 0, sizeof(filter_current_args));
	}
}

/**
 * filter_needs_deref() - Mark system call as ineligible for argument evaluation
 */
void filter_needs_deref(void) {
	struct filter_call_input *call = filter_input + current_nr;

	call->no_args = true;
}

/**
 * Use temporary filter_call_cur_args storage. When there's a new notification,
 * or the parser is done, we flush these argument matches to filter_input, and
 * check if they match (including no-matches) all the previous argument
 * specification. If they don't, the arguments can't be evaluated in the filter.
 */
void filter_add_arg(int index, struct bpf_arg arg) {
	struct filter_call_input *call = filter_input + current_nr;

	if (call->no_args)
		return;

	memcpy(filter_current_args.arg + index, &arg, sizeof(arg));
	filter_current_args.used = true;
}

unsigned int filter_close_input(void)
{
	struct notify *call = notify_call;
	int i, count = 0;

	filter_notify(-1);

	for (i = 0; i < 512; i++) {
		if (filter_input[i].notify) {
			count++;
			call->nr = i;

			if (filter_input[i].no_args)
				continue;

			memcpy(call->arg, filter_input[i].arg,
			       sizeof(call->arg));
		}
	}

	return count;
}

void filter_write(const char *path)
{
	struct sock_filter filter[MAX_FILTER];
	int fd, n;

	n = filter_close_input();
	n = filter_build(filter, n);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  S_IRUSR | S_IWUSR);
	write(fd, filter, sizeof(struct sock_filter) * n);
	close(fd);
}

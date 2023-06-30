
/* SPDX-License-Identifier: GPL-2.0-or-later
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

#include "util.h"

#include "filter.h"

#define N_SYSCALL			512
#define MAX_ENTRIES_PER_SYSCALL		16
#define MAX_FIELDS_PER_SYSCALL		16

const char *bpf_cmp_str[] = { "no check", "==", "!=", "<=", "<", ">=", ">",
			      "==", "!=" };

struct bpf_entry {
	struct bpf_field field[MAX_FIELDS_PER_SYSCALL];
};

/**
 * struct filter_call_input - First input stage for cooker notification requests
 * @notify:		Notify on this syscall
 * @ignore_args:	Don't filter on arguments for this syscall
 * @entry:		syscall notification entry with field checks
 */
struct filter_call_input {
	bool notify;
	bool ignore_args;
	unsigned int count;
	struct bpf_entry entry[MAX_ENTRIES_PER_SYSCALL];
} filter_input[N_SYSCALL] = { 0 };

static long current_nr;

/**
 * call_entry_count() - Input stage: count of entries for the same syscall
 * @nr:		syscall number
 *
 * Return: count of entries for the same syscall
 */
static unsigned int call_entry_count(long nr)
{
	struct filter_call_input *call = filter_input + nr;

	return call->count;
}

/**
 * entry_check_count() - Input stage: count of field checks for entry
 * @entry:	syscall entry with field checks
 *
 * Return: count of argument checks
 */
static unsigned entry_check_count(const struct bpf_entry *entry)
{
	unsigned i, n = 0;

	for (i = 0; i < MAX_FIELDS_PER_SYSCALL; i++)
		if (entry->field[i].cmp != NO_CHECK)
			n++;

	return n;
}

/**
 * filter_notify() - Start of notification request
 * @nr:		syscall number
 */
void filter_notify(long nr)
{
	struct filter_call_input *call = filter_input + nr;

	debug("   BPF: start filter information for #%lu", nr);
	current_nr = nr;
	call->notify = true;
}

/**
 * filter_add_check() - Add a new field check to the current syscall
 * @field:	 Field check specification
 */
void filter_add_check(struct bpf_field *field)
{
	struct filter_call_input *call = filter_input + current_nr;
	struct bpf_entry *entry;
	struct bpf_field *check;
	char buf[BUFSIZ];
	unsigned n;

	n = snprintf(buf, BUFSIZ, "   BPF: adding #%i %s %lu",
		     field->arg, bpf_cmp_str[field->cmp],
		     (field->type == BPF_U32) ? field->value.v32 :
						field->value.v64);

	if (field->cmp == AND_EQ || field->cmp == AND_NE) {
		snprintf(buf + n, BUFSIZ - n, " & %lu",
			 (field->type == BPF_U32) ? field->op2.v32 :
						    field->op2.v64);
	}

	debug("%s", buf);

	/* Too many entries or checks: ignore argument checks from now on */
	if (call_entry_count(current_nr) > MAX_ENTRIES_PER_SYSCALL)
		call->ignore_args = true;

	entry = &call->entry[call_entry_count(current_nr)];
	if (entry_check_count(entry) > MAX_FIELDS_PER_SYSCALL)
		call->ignore_args = true;

	if (call->ignore_args) {
		debug("   BPF: ignoring fields for syscall #%lu", current_nr);
		return;
	}

	check = &entry->field[entry_check_count(entry)];

	debug("   BPF: inserting check at %i for entry %i, syscall %lu",
	      entry_check_count(entry), call_entry_count(current_nr),
	      current_nr);

	memcpy(check, field, sizeof(*field));
}

void filter_needs_deref(void)
{
	struct filter_call_input *call = filter_input + current_nr;

	debug("   BPF: arguments for #%lu now ignored", current_nr);

	call->ignore_args = true;
}

void filter_flush_args(long nr)
{
	struct filter_call_input *call = filter_input + nr;
	struct bpf_entry *entry = &call->entry[(call->count)];

	if (entry_check_count(entry) > 0)
		call->count++;
	if (call->count > MAX_FIELDS_PER_SYSCALL)
		call->ignore_args = true;
}

/* Calculate how many instruction for the syscall */
static unsigned int get_n_args_syscall_instr(long nr)
{
	struct filter_call_input *call = filter_input + nr;
	unsigned int n = 0, total_instr = 0;
	unsigned int i, j;

	for (i = 0; i < call_entry_count(nr); i++) {
		const struct bpf_entry *entry = &call->entry[i];
		n = 0;

		for (j = 0; j < entry_check_count(entry); j++) {
			const struct bpf_field *field = &entry->field[j];
			enum bpf_cmp cmp = field->cmp;

			if (cmp == NO_CHECK)
				continue;

			switch (field->type) {
			case BPF_U32:
				/* For 32 bit fields
				 * comparison instructions (2):
				 *   1 loading the value + 1 for evaluation
				 * arithemtic instructions (3):
				 *   1 loading the value + 1 for the operation + 1 for evaluation
				 */
				if (cmp == AND_EQ || cmp == AND_NE)
					n += 3;
				else
					n += 2;
				break;
			case BPF_U64:
				/* For 64 bit fields: 32 instructions * 2
				 * for loading and evaluating the high and low 32 bits chuncks.
				*/
				if (cmp == AND_EQ || cmp == AND_NE)
					n += 6;
				else
					n += 4;
				break;
			}
		}
		total_instr += n;
		/* TODO: rewrite comment: If there at least an argument, then there is the jump to the
		 * notification */
		if (n > 0)
			total_instr++;
	}
	/* TODO: rewrite comment: If there at least an argument for that syscall, then there is the jump to the
	* accept */
	if (call_entry_count(nr))
		total_instr++;

	debug("  BPF: counted %i instructions for syscall %lu", total_instr, nr);

	return total_instr;
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

static unsigned int eq(struct sock_filter filter[],
		       const struct bpf_field *field, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (field->type) {
	case BPF_U64:
		hi = get_hi(field->value.v64);
		lo = get_lo(field->value.v64);
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = EQ(lo, 0, jfalse);
		filter[size++] = LOAD(HI_ARG(field->arg));
		filter[size++] = EQ(hi, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = EQ(field->value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int gt(struct sock_filter filter[],
		       const struct bpf_field *field, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (field->type) {
	case BPF_U64:
		hi = get_hi(field->value.v64);
		lo = get_lo(field->value.v64);
		filter[size++] = LOAD(HI_ARG(field->arg));
		filter[size++] = GT(hi, jtrue + 2, 0);
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = GT(lo, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = GT(field->value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int lt(struct sock_filter filter[],
		       const struct bpf_field *field, unsigned int jtrue,
		       unsigned int jfalse)
{
	unsigned int size = 0;
	uint32_t hi, lo;

	switch (field->type) {
	case BPF_U64:
		hi = get_hi(field->value.v64);
		lo = get_lo(field->value.v64);
		filter[size++] = LOAD(HI_ARG(field->arg));
		filter[size++] = LT(hi, jtrue + 2, jfalse);
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = LT(lo, jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = LT(field->value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int neq(struct sock_filter filter[],
			const struct bpf_field *field, unsigned int jtrue,
			unsigned int jfalse)
{
	return eq(filter, field, jfalse, jtrue);
}

static unsigned int ge(struct sock_filter filter[],
		       const struct bpf_field *field, unsigned int jtrue,
		       unsigned int jfalse)
{
	return lt(filter, field, jfalse, jtrue);
}

static unsigned int le(struct sock_filter filter[],
		       const struct bpf_field *field, unsigned int jtrue,
		       unsigned int jfalse)
{
	return gt(filter, field, jfalse, jtrue);
}

static unsigned int and_eq(struct sock_filter filter[],
			   const struct bpf_field *field, unsigned int jtrue,
			   unsigned int jfalse)
{
	unsigned int size = 0;

	switch (field->type) {
	case BPF_U64:
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = AND(get_lo(field->op2.v64));
		filter[size++] = EQ(get_lo(field->value.v64), 0, jfalse);
		filter[size++] = LOAD(HI_ARG(field->arg));
		filter[size++] = AND(get_hi(field->op2.v64));
		filter[size++] = EQ(get_hi(field->value.v64), jtrue, jfalse);
		break;
	case BPF_U32:
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = AND(field->op2.v32);
		filter[size++] = EQ(field->value.v32, jtrue, jfalse);
		break;
	}

	return size;
}

static unsigned int and_ne(struct sock_filter filter[],
			   const struct bpf_field *field, unsigned int jtrue,
			   unsigned int jfalse)
{
	unsigned int size = 0;

	switch (field->type) {
	case BPF_U64:
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = AND(get_lo(field->op2.v64));
		filter[size++] = EQ(get_lo(field->value.v64), 0, jtrue + 3);
		filter[size++] = LOAD(HI_ARG(field->arg));
		filter[size++] = AND(get_hi(field->op2.v64));
		filter[size++] = EQ(get_hi(field->value.v64), jfalse, jtrue);
		break;
	case BPF_U32:
		filter[size++] = LOAD(LO_ARG(field->arg));
		filter[size++] = AND(field->op2.v32);
		filter[size++] = EQ(field->value.v32, jfalse, jtrue);
		break;
	}

	return size;
}

static unsigned int insert_args(struct sock_filter filter[], long nr)
{
	struct filter_call_input *call = filter_input + nr;
	unsigned int next_offset, n_checks = 0;
	unsigned int count = call_entry_count(nr);
	struct bpf_entry *entry;
	unsigned int offset = 0;
	unsigned int size = 0;
	unsigned int i, j;

	/* No entries, hence no arguments for the @nr syscall */
	if (count <= 0)
		return 0;
	for (i = 0; i < count; i++) {
		n_checks = 0;
		entry = &call->entry[i];
		/* If there are multiple entries for the syscall @nr, then the next group
	         * of arguments to check (i.e. the next offset) is after the number of
	         * arguments of the current entry. The next_offset is used to
		 * jump to the next group if the check is false.
		 */
		next_offset = entry_check_count(entry);
		for (j = 0; j <= entry_check_count(entry); j++) {
			struct bpf_field *field = &entry->field[j];
			/* If the current argument isn't the last argument (offset = 1),
			 * add an additional jump as there is seccomp notify instruction
			 * before the allow one.
			 */
			offset = next_offset - n_checks;
			offset += (offset > 1) ? 1 : 0;
			switch (field->cmp) {
			case NO_CHECK:
				continue;
			case EQ:
				size += eq(&filter[size],     field, 0, offset);
				break;
			case NE:
				size += neq(&filter[size],    field, 0, offset);
				break;
			case GT:
				size += gt(&filter[size],     field, 0, offset);
				break;
			case LT:
				size += lt(&filter[size],     field, 0, offset);
				break;
			case GE:
				size += ge(&filter[size],     field, 0, offset);
				break;
			case LE:
				size += le(&filter[size],     field, 0, offset);
				break;
			case AND_EQ:
				size += and_eq(&filter[size], field, 0, offset);
				break;
			case AND_NE:
				size += and_ne(&filter[size], field, 0, offset);
				break;
			}
			n_checks++;
		}
		if (n_checks > 0)
			filter[size++] = STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
	}
	filter[size++] = STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

	return size;
}

unsigned int filter_build(struct sock_filter filter[], unsigned n)
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

	debug("  BPF: tree has %i nodes", n_nodes);

	/* Pre */
	/* cppcheck-suppress badBitmaskCheck */
	filter[size++] = STMT(BPF_LD | BPF_W | BPF_ABS,
			      offsetof(struct seccomp_data, arch));
	filter[size++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			      SEITAN_AUDIT_ARCH, 1, 0);
	filter[size++] = STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	/* cppcheck-suppress badBitmaskCheck */
	filter[size++] = STMT(BPF_LD | BPF_W | BPF_ABS,
			      offsetof(struct seccomp_data, nr));

	/* pre-check instruction + load syscall number (4 instructions) */
	accept = size + n_nodes + n;
	notify = accept + 1;

	/* Insert nodes */
	for (i = 0; i < n_nodes; i++) {
		if (nodes[i] == EMPTY) {
			filter[size++] = JUMPA(accept - size);
		} else {
			nr = get_syscall(nodes[i]);
			offset_left = left_child(i) - i - 1;
			offset_right = right_child(i) - i - 1;
			filter[size++] = JGE(nr, offset_right, offset_left);
		}
	}

	next_offset = n + 1;
	/* Insert leaves */
	for (i = 0; i < n; i++) {
		nr = get_syscall(i);
		if (call_entry_count(nr) > 0) {
			offset = next_offset;
		} else {
			/* If the syscall doesn't have any arguments, then notify */
			offset = notify - size - 1;
		}
		filter[size++] = EQ(nr, offset, accept - size);
		/* The arguments block of the next entry are after the total
		 * number of the instructions for checking the arguments of the current entry
		 */
		next_offset += get_n_args_syscall_instr(nr) - 1;
	}
	/* Seccomp accept and notify instruction */
	filter[size++] = STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	filter[size++] = STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);

	/*
	 * Insert args. It sequentially checks all the arguments for a syscall
	 * entry. If a check on the argument isn't equal then it jumps to
	 * check the following entry of the syscall and its arguments.
	 */
	for (i = 0; i < n; i++)
		size += insert_args(&filter[size], get_syscall(i));

	debug("  BPF: filter with %i call%s has %i instructions",
	      n, n != 1 ? "s" : "", size);

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

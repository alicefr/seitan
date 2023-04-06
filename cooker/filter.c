#define _GNU_SOURCE
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "numbers.h"
#include "filter.h"
#include "util.h"

#define N_SYSCALL sizeof(numbers) / sizeof(numbers[0])

static int compare_key(const void *key, const void *base)
{
	return strcmp((const char *)key,
		      ((struct syscall_numbers *)base)->name);
}

int compare_bpf_call_names(const void *a, const void *b)
{
	return strcmp(((struct bpf_call *)a)->name,
		      ((struct bpf_call *)b)->name);
}

static int compare_table_nr(const void *a, const void *b)
{
	return (((struct syscall_entry *)a)->nr -
		((struct syscall_entry *)b)->nr);
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

long resolve_syscall_nr(const char *name)
{
	struct syscall_numbers *p;
	p = (struct syscall_numbers *)bsearch(
		name, numbers, sizeof(numbers) / sizeof(numbers[0]),
		sizeof(numbers[0]), compare_key);
	if (p == NULL)
		return -1;
	return p->number;
}

/*
 * Construct a syscall tables ordered by increasing syscall number
 * @returns number of syscall entries in the table
 */
int construct_table(const struct bpf_call *entries, int n,
		    struct syscall_entry *table)
{
	long nr;
	unsigned int tn;
	int i;

	tn = 0;
	for (i = 0; i < n; i++) {
		table[i].count = 0;
		table[i].entry = NULL;
	}

	for (i = 0; i < n; i++) {
		if (tn > N_SYSCALL - 1)
			return -1;
		if (i > 0) {
			if (strcmp((entries[i]).name, (entries[i - 1]).name) ==
			    0) {
				table[tn - 1].count++;
				continue;
			}
		}
		nr = resolve_syscall_nr((entries[i]).name);
		if (nr < 0) {
			fprintf(stderr, "wrong syscall number for %s\n",
				(entries[i]).name);
			continue;
		}
		table[tn].entry = &entries[i];
		table[tn].count++;
		table[tn].nr = nr;
		tn++;
	}
	qsort(table, tn, sizeof(struct syscall_entry), compare_table_nr);

	return tn;
}

static unsigned get_n_args_syscall_entry(const struct bpf_call *entry)
{
	unsigned i, n = 0;

	for (i = 0; i < 6; i++)
		if (entry->args[i].cmp != NO_CHECK)
			n++;
	return n;
}

static unsigned get_n_args_syscall(const struct syscall_entry *table)
{
	unsigned i, n = 0;

	for (i = 0; i < table->count; i++)
		n += get_n_args_syscall_entry(table->entry + i);

	return n;
}

static unsigned int get_n_args_syscall_instr(const struct syscall_entry *table)
{
	const struct bpf_call *entry;
	bool has_arg = false;
	unsigned n = 0, total_instr = 0;

	for (unsigned int i = 0; i < table->count; i++) {
		entry = table->entry + i;
		n = 0;
		for (unsigned int k = 0; k < 6; k++) {
			if (entry->args[k].cmp == NO_CHECK)
				continue;
			switch (entry->args[k].type) {
			case U32:
				/* For 32 bit arguments: 2 instructions,
				 * 1 for loading the value and
				 * 1 for evaluating the  argument */
				n += 2;
				break;
			case U64:
				/* For 64 bit arguments: 4 instructions, for
				 * loading and evaluating the high and low 32
				 * bits chuncks.
				*/
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

static unsigned int get_total_args_instr(const struct syscall_entry table[],
					 unsigned int n_syscall)
{
	unsigned i, n = 0;

	for (i = 0; i < n_syscall; i++) {
			n += get_n_args_syscall_instr(&table[i]);
	}
	return n;
}

static bool check_args_syscall_entry(const struct bpf_call *entry){
	return entry->args[0].cmp != NO_CHECK ||
	       entry->args[1].cmp != NO_CHECK ||
	       entry->args[2].cmp != NO_CHECK ||
	       entry->args[3].cmp != NO_CHECK ||
	       entry->args[4].cmp != NO_CHECK || entry->args[5].cmp != NO_CHECK;
}

static bool check_args_syscall(const struct syscall_entry *table)
{
	for (unsigned int i = 0; i < table->count; i++) {
		if (check_args_syscall_entry(table->entry + i))
			return true;
	}
	return false;
}

unsigned int create_bpf_program_log(struct sock_filter filter[])
{
	filter[0] = (struct sock_filter)BPF_STMT(
		BPF_LD | BPF_W | BPF_ABS,
		(offsetof(struct seccomp_data, arch)));
	filter[1] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						 SEITAN_AUDIT_ARCH, 0, 1);
	filter[2] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						 SECCOMP_RET_USER_NOTIF);
	filter[3] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						 SECCOMP_RET_ALLOW);
	return 4;
}

static unsigned int eq_u64_filter(struct sock_filter filter[], int idx,
				  uint64_t v, unsigned int jtrue,
				  unsigned int jfalse)
{
	uint32_t hi = get_hi(v);
	uint32_t lo = get_lo(v);

	filter[0] = (struct sock_filter)LOAD(LO_ARG(idx));
	filter[1] = (struct sock_filter)EQ(lo, 0, jfalse);
	filter[2] = (struct sock_filter)LOAD(HI_ARG(idx));
	filter[3] = (struct sock_filter)EQ(hi, jtrue, jfalse);

	return 4;
}

unsigned int create_bfp_program(struct syscall_entry table[],
				struct sock_filter filter[],
				unsigned int n_syscall)
{
	unsigned int offset_left, offset_right;
	const struct bpf_call *entry;
	unsigned int n_args, n_nodes;
	unsigned int notify, accept;
	unsigned int i, j, k, size;
	unsigned int next_offset, offset;
	unsigned int next_args_off;
	int nodes[MAX_JUMPS];

	create_lookup_nodes(nodes, n_syscall);

	/* First 3 checks */
	size = 3;
	/* No nodes if there is a single syscall */
	n_nodes = (1 << count_shift_right(n_syscall - 1)) - 1;

	n_args = get_total_args_instr(table, n_syscall);

	/* pre-check instruction + load syscall number (4 instructions) */
	accept = 3 + n_nodes + n_syscall + n_args;
	notify = accept + 1;

	/* Pre */
	/* cppcheck-suppress badBitmaskCheck */
	filter[0] = (struct sock_filter)BPF_STMT(
		BPF_LD | BPF_W | BPF_ABS,
		(offsetof(struct seccomp_data, arch)));
	filter[1] = (struct sock_filter)BPF_JUMP(
		BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, accept - 2);
	/* cppcheck-suppress badBitmaskCheck */
	filter[2] = (struct sock_filter)BPF_STMT(
		BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)));

	/* Insert nodes */
	for (i = 0; i < n_nodes; i++) {
		if (nodes[i] == EMPTY) {
			filter[size++] =
				(struct sock_filter)JUMPA(accept - size);
		} else {
			offset_left = left_child(i) - i - 1;
			offset_right = right_child(i) - i - 1;
			filter[size++] = (struct sock_filter)JGE(
				table[nodes[i]].nr, offset_right, offset_left);
		}
	}

	next_offset = n_syscall - 1;
	/* Insert leaves */
	for (i = 0; i < n_syscall; i++) {
		/* If the syscall doesn't have any arguments, jump directly to
		 * the notification
		 */
		if (check_args_syscall(&table[i]))
			offset = next_offset;
		else
			offset = notify - size - 1;
		filter[size++] = (struct sock_filter)EQ(table[i].nr, offset,
							accept - size);
		next_offset += get_n_args_syscall(&table[i]);
	}

	/*
	 * Insert args. It sequentially checks all the arguments for a syscall
	 * entry. If a check on the argument isn't equal then it jumps to
	 * check the following entry of the syscall and its arguments.
	 */
	for (i = 0; i < n_syscall; i++) {
		bool has_arg = false;
		for (j = 0; j < (table[i]).count; j++) {
			unsigned n_checks = 0;
			entry = table[i].entry + j;
			next_args_off = get_n_args_syscall_entry(entry);
			for (k = 0; k < 6; k++) {
				if (entry->args[k].cmp == NO_CHECK)
					continue;
				offset = next_args_off - n_checks;
				switch (entry->args[k].type) {
				case U64:
					size += eq_u64_filter(
						&filter[size], k,
						entry->args[k].value.v64, 0,
						offset);
					n_checks++;
					has_arg = true;
					break;
				case U32:
					filter[size++] = (struct sock_filter)
						LOAD((offsetof(
							struct seccomp_data,
							args[k])));
					filter[size++] = (struct sock_filter)EQ(
						entry->args[k].value.v32, 0,
						offset);
					n_checks++;
					has_arg = true;
					break;
				default:
					fprintf(stderr,
						"value for args not recognized\n");
					return -1;
				}
			}
			if (check_args_syscall_entry(table[i].entry))
				filter[size++] = (struct sock_filter)JUMPA(
					notify - size);
		}
		/* At this point none of the checks was positive, it jumps to
		 * the default behavior
		 */
		if (has_arg)
			filter[size++] =
				(struct sock_filter)JUMPA(accept - size);
	}

	/* Seccomp accept and notify instruction */
	filter[size++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						      SECCOMP_RET_ALLOW);
	filter[size++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						      SECCOMP_RET_USER_NOTIF);
	return size;
}

static int compare_names(const void *a, const void *b)
{
	return strcmp(((struct syscall_numbers *)a)->name,
		      ((struct syscall_numbers *)b)->name);
}

int convert_bpf(char *file, struct bpf_call *entries, int n, bool log)
{
	int nt, fd, fsize;
	struct syscall_entry table[N_SYSCALL];
	struct sock_filter filter[MAX_FILTER];

	qsort(numbers, sizeof(numbers) / sizeof(numbers[0]), sizeof(numbers[0]),
	      compare_names);

	qsort(entries, n, sizeof(struct bpf_call), compare_bpf_call_names);
	nt = construct_table(entries, n, table);

	if (log)
		fsize = create_bpf_program_log(filter);
	else
		fsize = create_bfp_program(table, filter, nt);

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  S_IRUSR | S_IWUSR);
	write(fd, filter, sizeof(struct sock_filter) * fsize);

	close(fd);

	return 0;
}

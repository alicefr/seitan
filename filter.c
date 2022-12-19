#define _GNU_SOURCE
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "numbers.h"
#include "filter.h"

#define N_SYSCALL sizeof(numbers) / sizeof(numbers[0])

const int LEAF_SIZE = 1;
const int NODE_SIZE = 2;
const int ARG_SIZE = 1;
const int NOTIFY = 1;
const int ACCEPT = 2;

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

//static void print_table(struct syscall_entry *table, int n)
//{
//	int i;
//	printf("-----------------------\n");
//	for (i = 0; i < n; i++) {
//		printf("nr=%ld n=%d entry=%s\n", table[i].nr, table[i].count,
//		       (table[i].entry)->name);
//	}
//	printf("-----------------------\n");
//}

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

static unsigned get_n_args(const struct syscall_entry *table)
{
	unsigned i, k, n;
	n = 0;
	for (i = 0; i < table->count; i++)
		for (k = 0; k < 6; k++)
			if ((table->entry + i)->check_arg[k])
				n++;
	return n;
}

static unsigned int get_total_args(const struct syscall_entry table[],
			    unsigned int n_syscall)
{
	unsigned int i, n;
	n = 0;
	for (i = 0; i < n_syscall; i++) {
		n += get_n_args(&table[i]);
	}
	return n;
}

unsigned int create_bfp_program(struct syscall_entry table[],
		struct sock_filter filter[],
		unsigned int n_syscall)
{
	unsigned int offset_left, offset_right;
	unsigned int n_args, n_nodes;
	unsigned int notify, accept;
	unsigned int i,j,k, size;
	unsigned int empty;
	int nodes[MAX_JUMPS];

	create_lookup_nodes(nodes, n_syscall);

	empty = 0;
	size = 2;
	n_nodes = count_nodes(nodes);
	n_args = get_total_args(table, n_syscall);

	/*
	 * Total number of instructions =
	 * 	offset preinstructions + n nodes
	 * 	+ n syscalls (instruction + ja to end) + total args
	 */
	accept = size + n_nodes + 2 * n_syscall + n_args - 2;
	notify = size + n_nodes + 2 * n_syscall + n_args - 1;

	/* Pre */
	/* cppcheck-suppress badBitmaskCheck */
	filter[0] = (struct sock_filter)BPF_STMT(
			BPF_LD | BPF_W | BPF_ABS,
			(offsetof(struct seccomp_data, arch)));
	filter[1] = (struct sock_filter)BPF_JUMP(
			BPF_JMP | BPF_JEQ | BPF_K, SEITAN_AUDIT_ARCH, 0, size - 4);
	/* cppcheck-suppress badBitmaskCheck */
	filter[2] = (struct sock_filter)BPF_STMT(
			BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)));

	/* Insert nodes */
	for (i = 0; i < n_nodes; i++) {
		if (nodes[i] == EMPTY) {
			empty++;
			continue;
		}
		offset_left = left_child(i) - i - 1 - empty;
		offset_right = right_child(i) - i - 1 - empty;

		printf("i=%d nr=%ld node %d offset_right=%d offset_left=%d\n",
				i, table[nodes[i]].nr, nodes[i], offset_right,
				offset_left);
		filter[size] = (struct sock_filter)JGE(
				table[nodes[i]].nr, offset_right, offset_left);
		size++;
	}

	/* Insert leaves */
	for (i = 0; i < n_syscall; i++) {
		filter[size++] = (struct sock_filter)EQ(
				table[i].nr, notify - size, accept - size);
	}

	/*
	 * Insert args: evaluate every args, if it doesn't match continue with
	 * the following, otherwise notify.
	 */
	for (i = 0; i < n_syscall; i++) {
		for (j = 0; j < table->count; j++) {
			for (k = 0; k < 6; k++)
				if ((table[i].entry + j)->check_arg[k])
					filter[size++] = (struct sock_filter)EQ(
							(table[i].entry + j)->args[k],
							notify - size, 0);

		}
		filter[size++] = (struct sock_filter) JUMPA(accept - size);
	}

	/* Seccomp accept and notify instruction */
	filter[size - 2] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
			SECCOMP_RET_ALLOW);
	filter[size - 1] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
			SECCOMP_RET_USER_NOTIF);
	printf("It should be 0 got %d \n", notify + 1 - size);
	return size;
}

static int compare_names(const void *a, const void *b)
{
        return strcmp(((struct syscall_numbers *)a)->name,
                      ((struct syscall_numbers *)b)->name);
}

int convert_bpf(char *file, struct bpf_call *entries, int n)
{
	int nt, fd, fsize;
	size_t nwrite;
	struct syscall_entry table[N_SYSCALL];
	struct sock_filter filter[MAX_FILTER];

        qsort(numbers, sizeof(numbers) / sizeof(numbers[0]), sizeof(numbers[0]),
              compare_names);

	qsort(entries, n, sizeof(struct bpf_call), compare_bpf_call_names);
	nt = construct_table(entries, n, table);

	fsize = create_bfp_program(table, filter, nt);

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  S_IRUSR | S_IWUSR);
	nwrite = write(fd, filter, sizeof(struct sock_filter) * fsize);
	printf("written %ld entries\n", nwrite / sizeof(struct sock_filter));
	close(fd);

	return 0;
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

static unsigned count_shift_right(unsigned int n)
{
	unsigned int i = 0;
	for (; n > 0; i++) {
		n = n >> 1;
	}
	return i;
}

void print_nodes(int nodes[])
{
	unsigned int i;
	for (i = 0; i < 20; i++)
		printf("%d\n", nodes[i]);
}

unsigned int count_nodes(int jumps[])
{
	unsigned int i = 0;
	unsigned int empty = 0;

	for (; empty < 2 && i < MAX_JUMPS; i++) {
		if (jumps[i] == EMPTY)
			empty++;
	}
	if (empty > 0) {
		i -= empty;
	}
	return i;
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
	unsigned old_interval, interval;

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
//void main(void) {
//	int parent;
//	parent =0;
//	printf("parent %d left=%d right= %d\n", parent, left_child(parent), right_child(parent));
//	parent =1;
//	printf("parent %d left=%d right= %d\n", parent, left_child(parent), right_child(parent));
//	parent =2;
//	printf("parent %d left=%d right= %d\n", parent, left_child(parent), right_child(parent));
//	parent =3;
//	printf("parent %d left=%d right= %d\n", parent, left_child(parent), right_child(parent));
//	parent =4;
//	printf("parent %d left=%d right= %d\n", parent, left_child(parent), right_child(parent));
//	parent =5;
//	printf("parent %d left=%d right= %d\n", parent, left_child(parent), right_child(parent));
//	parent =6;
//	printf("parent %d left=%d right= %d\n", parent, left_child(parent), right_child(parent));
//	parent =7;
//	printf("parent %d left=%d right= %d\n", parent, left_child(parent), right_child(parent));
//}

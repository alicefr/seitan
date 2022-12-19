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

#include "tree.h"
#include "numbers.h"
#include "filter.h"

static int compare_names(const void *a, const void *b)
{
	return strcmp(((struct syscall_numbers *)a)->name,
		      ((struct syscall_numbers *)b)->name);
}

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

int convert_bpf(char *file, struct bpf_call *entries, int n)
{
	int nt, fd, fsize;
	size_t nwrite;
	struct syscall_entry table[N_SYSCALL];
	struct sock_filter filter[MAX_FILTER];

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

struct bpf_call calls[] = {
	{
		.name = "connect",
		.args = { 0, 111, 0, 0, 0, 0 },
		.check_arg = { false, false, false, false, false, false },
	},
/*	{
		.name = "openat",
		.args = { 123, 0, 0, 0, 0, 0 },
		.check_arg = { true, false, false, false, false, false },
	},
	{
		.name = "openat",
		.args = { 123, 123, 0, 0, 0, 0 },
		.check_arg = { true, true, false, false, false, false },
	},
	{
		.name = "wrong",
		.args = { 123, 0, 0, 0, 0, 0 },
		.check_arg = { true, false, false, false, false, false },
	},
	{
		.name = "socket",
		.args = { 0, 555, 0, 0, 0, 0 },
		.check_arg = { true, true, true, false, false, false },
	},
	{
		.name = "socket",
		.args = { 0, 555, 0, 0, 0, 0 },
		.check_arg = { true, true, true, false, false, false },
	},
	{
		.name = "openat",
		.args = { 123, 123, 0, 0, 0, 0 },
		.check_arg = { true, true, false, false, false, false },
	},
	{
		.name = "accept",
		.args = { 123, 123, 0, 0, 0, 0 },
		.check_arg = { true, true, false, false, false, false },
	},
	{
		.name = "bind",
		.args = { 123, 123, 0, 0, 0, 0 },
		.check_arg = { true, true, false, false, false, false },
	},
	{
		.name = "sendmmsg",
		.args = { 123, 123, 0, 0, 0, 0 },
		.check_arg = { true, true, false, false, false, false },
	},
	{
		.name = "mount",
		.args = { 123, 123, 0, 0, 0, 0 },
		.check_arg = { true, true, false, false, false, false },
	},
*/
};

int main(int argc, char **argv)
{
	int ret;
	if (argc < 2) {
		perror("missing input file");
		exit(EXIT_FAILURE);
	}
	qsort(numbers, sizeof(numbers) / sizeof(numbers[0]), sizeof(numbers[0]),
	      compare_names);
	ret = convert_bpf(argv[1], calls, sizeof(calls) / sizeof(calls[0]));
	if (ret < 0) {
		perror("converting bpf program");
		exit(EXIT_FAILURE);
	}
	return 0;
}

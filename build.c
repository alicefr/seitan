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

/*
 * Construct a syscall tables ordered by increasing syscall number
 * @returns number of syscall entries in the table
 */
int construct_table(struct bpf_call *entries, int n,
		    struct syscall_entry *table)
{
	long nr;
	int i, tn, n_syscalls;

	tn = 0;
	nr = 0;
	n_syscalls = sizeof(numbers) / sizeof(numbers[0]);
	for (i = 0; i < n; i++) {
		if (tn > n_syscalls - 1)
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

void create_bfp_program_from_tree(struct sock_filter *filter, struct node *root,
				  int size)
{
	struct sock_filter *t;
	int *s;

	s = malloc(sizeof(int));
	*s = size - 3;

	/* Pre */
	/* cppcheck-suppress badBitmaskCheck */
	filter[0] = (struct sock_filter)BPF_STMT(
		BPF_LD | BPF_W | BPF_ABS,
		(offsetof(struct seccomp_data, arch)));
	filter[1] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						 SEITAN_AUDIT_ARCH, 0, size - 4);
	/* cppcheck-suppress badBitmaskCheck */
	filter[2] = (struct sock_filter)BPF_STMT(
		BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)));

	t = filter + 3;
	calculate_depth_left(root);
	node_bpf_instr(root, &t, s);
	if (*s > 0) {
		fprintf(stderr, "remaining instr %d \n", *s);
	}

	/* Post */
	filter[size - 2] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
							SECCOMP_RET_ALLOW);
	filter[size - 1] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
							SECCOMP_RET_USER_NOTIF);
	free(s);
}

int convert_bpf(char *file, struct bpf_call *entries, int n)
{
	int nt, fd, tsize;
	size_t nwrite;
	struct syscall_entry *table;
	struct node *root;
	struct sock_filter *filter;

	table = calloc(sizeof(numbers) / sizeof(numbers[0]),
		       sizeof(struct syscall_entry));
	qsort(entries, n, sizeof(struct bpf_call), compare_bpf_call_names);
	nt = construct_table(entries, n, table);

	root = create_bst_tree(table, 0, nt - 1);
	print_level_order(root);

	/* Five instructions are added for the pre and post */
	tsize = calculate_size(root) + 5;
	filter = calloc(tsize, sizeof(struct sock_filter));

	create_bfp_program_from_tree(filter, root, tsize);

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  S_IRUSR | S_IWUSR);
	nwrite = write(fd, filter, sizeof(struct sock_filter) * tsize);
	printf("written %ld entries\n", nwrite / sizeof(struct sock_filter));
	close(fd);
	free(table);
	free_tree(root);

	return 0;
}

struct bpf_call calls[] = {
	{
		.name = "connect",
		.args = { 0, 111, 0, 0, 0, 0 },
		.check_arg = { false, true, false, false, false, false },
	},
	{
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

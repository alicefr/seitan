#ifndef FILTER_H_
#define FILTER_H_

#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/seccomp.h>

#define JGE(nr, right, left) \
	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (nr), (right), (left))
#define JUMPA(jump) BPF_JUMP(BPF_JMP | BPF_JA, (jump), 0, 0)
#define EQ(nr, a1, a2) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), (a1), (a2))
#define LOAD(x) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (x))

#define MAX_FILTER 1024

#define MAX_JUMPS 128
#define EMPTY -1

struct bpf_call {
	char *name;
	int args[6];
	bool check_arg[6];
};

struct syscall_entry {
	unsigned int count;
	long nr;
	const struct bpf_call *entry;
};

void create_lookup_nodes(int jumps[], unsigned int n);
unsigned int left_child(unsigned int parent_index);
unsigned int right_child(unsigned int parent_index);

unsigned int create_bfp_program(struct syscall_entry table[],
				struct sock_filter filter[],
				unsigned int n_syscall);
int convert_bpf(char *file, struct bpf_call *entries, int n, bool log);

#endif

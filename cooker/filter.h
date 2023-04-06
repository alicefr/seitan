#ifndef FILTER_H_
#define FILTER_H_

#include <stdint.h>

#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/seccomp.h>

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
#define LOAD(x) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (x))
#define MAX_FILTER 1024

#define MAX_JUMPS 128
#define EMPTY -1

enum arg_type { U32, U64 };

union arg_value {
	uint32_t v32;
	uint64_t v64;
};

enum arg_cmp { NO_CHECK, EQ, NE, LE, LT, GE, GT, AND_EQ, AND_NE };

struct arg {
	union arg_value value;
	enum arg_type type;
	enum arg_cmp cmp;
	union arg_value op2;
};

struct bpf_call {
	char *name;
	struct arg args[6];
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

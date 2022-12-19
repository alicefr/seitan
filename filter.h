#ifndef FILTER_H
#define FILTER_H

#define JGE(nr, right, left) \
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (nr), (right), (left))
#define JUMPA(jump)  BPF_JUMP(BPF_JMP | BPF_JA, (jump), 0, 0)
#define EQ(nr, a1, a2) \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), (a1), (a2))

#define MAX_FILTER 1024
#define N_SYSCALL sizeof(numbers) / sizeof(numbers[0])

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

int convert_bpf(char *file, struct bpf_call *entries, int n);

#endif

#ifndef TREE_H
#define TREE_H

struct bpf_call {
        char *name;
        int args[6];
        bool check_arg[6];
};

struct syscall_entry {
        int count;
        long nr;
        struct bpf_call *entry;
};

struct node {
        unsigned depth_left;
        struct syscall_entry *t;
        struct node *left;
        struct node *right;
};

struct node *new_node(struct syscall_entry *t);
struct node *create_bst_tree(struct syscall_entry *table, int start, int end);
void free_tree(struct node *node);
int calculate_depth_left(struct node *node);
void print_level_order(struct node *root);
int calculate_size(const struct node *node);
void node_bpf_instr(const struct node *node, struct sock_filter **filter, int *size);


#endif

#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

#include "tree.h"

#define JUMP(nr, right, left) \
	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (nr), (left), (right))
#define JUMPA(jump)  BPF_JUMP(BPF_JMP | BPF_JA, (jump), 0, 0)
#define EQ(nr, a1, a2) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), (a1), (a2))

const int LEAF_SIZE = 1;
const int NODE_SIZE = 2;
const int ARG_SIZE = 1;
const int NOTIFY = 1;
const int ACCEPT = 2;

struct node *new_node(struct syscall_entry *t)
{
        struct node *n = (struct node *)malloc(sizeof(struct node));
        n->depth_left = 0;
        n->t = t;
        n->left = NULL;
        n->right = NULL;

        return n;
}

struct node *create_bst_tree(struct syscall_entry *table, int start, int end)
{
	int mid;
	struct node *root;

	if (start > end)
		return NULL;
	mid = (start + end) / 2;
	root = new_node(&table[mid]);
	root->left = create_bst_tree(table, start, mid - 1);
	root->right = create_bst_tree(table, mid + 1, end);

	return root;
}

void free_tree(struct node *node)
{
	if (node == NULL)
		return;
	free_tree(node->left);
	free_tree(node->right);
	free(node);
}

static int get_n_arguments(const struct node *node)
{
	int n_options = 0;
	for (int i= 0 ; i<node->t->count;  i++){
		for (int k=0; k < 6; k++)
			if ((node->t->entry+i)->check_arg[k])
				n_options++;
	}
	return n_options;
}

int calculate_depth_left(struct node *node)
{
	int size;
	if (node == NULL)
		return 0;
	if (node->left == NULL)
		size = LEAF_SIZE + ARG_SIZE +
			get_n_arguments(node)* ARG_SIZE;
	else
		size = calculate_depth_left(node->left)
			+ NODE_SIZE + ARG_SIZE + get_n_arguments(node)* ARG_SIZE;
	node->depth_left = size;
	return size;
}

int calculate_size(const struct node *node) {
	if (node == NULL)
		return 0;
	if (node->left == NULL && node-> right == NULL)
		return LEAF_SIZE + ARG_SIZE + get_n_arguments(node) * ARG_SIZE;
	return calculate_size(node->left) + calculate_size(node->right)
		+ NODE_SIZE + ARG_SIZE + get_n_arguments(node)* ARG_SIZE ;
}

static int height(struct node *node)
{
       if (node == NULL)
               return 0;
       else {
               int lheight = height(node->left);
               int rheight = height(node->right);

               if (lheight > rheight) {
                       return (lheight + 1);
               } else {
                       return (rheight + 1);
               }
       }
}

static void print_level(struct node *root, int level)
{
	if (root == NULL)
		return;
	if (level == 1)
		printf("%ld ", (root->t)->nr);
	else if (level > 1) {
		print_level(root->left, level - 1);
		print_level(root->right, level - 1);
	}
}

void print_level_order(struct node *root)
{
	int h = height(root);
	int i;
	for (i = 1; i <= h; i++) {
		print_level(root, i);
		printf("\n");
	}
}

static void add_instr(struct sock_filter **filter, struct sock_filter instr, int *size)
{
	**filter = instr;
	(*filter)++;
	(*size)--;
}

static void add_args(const struct node *node, struct sock_filter **filter, int *size)
{
	/* the instruction doesn't have any arguments */
	if ( node->t->count < 1) {
		add_instr(filter, (struct sock_filter) JUMPA(*size - NOTIFY -1), size);
	}
	for (int i = 0 ; i<node->t->count;  i++){
		for (int k=0; k < 6; k++)
			if ((node->t->entry+i)->check_arg[k]) {
				add_instr(filter, (struct sock_filter)
						EQ((node->t->entry+i)->args[k], *size - NOTIFY -1, 0),
						size);
			}
		add_instr(filter, (struct sock_filter) JUMPA(*size - ACCEPT -1), size);
	}
}

void node_bpf_instr(const struct node *node, struct sock_filter **filter, int *size)
{
	int n_args;
	if (node == NULL)
		return;
	/* Leaf */
	if (node->left == NULL && node->right == NULL) {
		add_instr(filter,
				(struct sock_filter)JUMP(node->t->nr, 0, *size - ACCEPT -1),
				size);
		add_args(node, filter, size);
	} else {
		add_instr(filter, (struct sock_filter) EQ(node->t->nr, 1, 0), size);

		n_args = get_n_arguments(node) + 1;
		add_instr(filter, (struct sock_filter)JUMP(node->t->nr, n_args,
						    node->depth_left), size);
		add_args(node, filter, size);

		node_bpf_instr(node->left, filter, size);
		node_bpf_instr(node->right, filter, size);
	}
}

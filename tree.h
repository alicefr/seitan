#ifndef TREE_H
#define TREE_H

#define MAX_JUMPS 128
#define EMPTY -1

void create_lookup_nodes(int jumps[], unsigned int n);
unsigned int count_nodes(int jumps[]);
unsigned int left_child(unsigned int parent_index);
unsigned int right_child(unsigned int parent_index);
void print_nodes(int nodes[]);

#endif

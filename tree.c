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

const int LEAF_SIZE = 1;
const int NODE_SIZE = 2;
const int ARG_SIZE = 1;
const int NOTIFY = 1;
const int ACCEPT = 2;

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

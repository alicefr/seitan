#define _GNU_SOURCE
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/filter.h>


#define SIZE_FILTER 1024

/* From linux tools/bpf/bpf_dbg.c */
#define BPF_LDX_B	(BPF_LDX | BPF_B)
#define BPF_LDX_W	(BPF_LDX | BPF_W)
#define BPF_JMP_JA	(BPF_JMP | BPF_JA)
#define BPF_JMP_JEQ	(BPF_JMP | BPF_JEQ)
#define BPF_JMP_JGT	(BPF_JMP | BPF_JGT)
#define BPF_JMP_JGE	(BPF_JMP | BPF_JGE)
#define BPF_JMP_JSET	(BPF_JMP | BPF_JSET)
#define BPF_ALU_ADD	(BPF_ALU | BPF_ADD)
#define BPF_ALU_SUB	(BPF_ALU | BPF_SUB)
#define BPF_ALU_MUL	(BPF_ALU | BPF_MUL)
#define BPF_ALU_DIV	(BPF_ALU | BPF_DIV)
#define BPF_ALU_MOD	(BPF_ALU | BPF_MOD)
#define BPF_ALU_NEG	(BPF_ALU | BPF_NEG)
#define BPF_ALU_AND	(BPF_ALU | BPF_AND)
#define BPF_ALU_OR	(BPF_ALU | BPF_OR)
#define BPF_ALU_XOR	(BPF_ALU | BPF_XOR)
#define BPF_ALU_LSH	(BPF_ALU | BPF_LSH)
#define BPF_ALU_RSH	(BPF_ALU | BPF_RSH)
#define BPF_MISC_TAX	(BPF_MISC | BPF_TAX)
#define BPF_MISC_TXA	(BPF_MISC | BPF_TXA)
#define BPF_LD_B	(BPF_LD | BPF_B)
#define BPF_LD_H	(BPF_LD | BPF_H)
#define BPF_LD_W	(BPF_LD | BPF_W)
static const char * const op_table[] = {
        [BPF_ST]        = "st",
        [BPF_STX]       = "stx",
        [BPF_LD_B]      = "ldb",
        [BPF_LD_H]      = "ldh",
        [BPF_LD_W]      = "ld",
        [BPF_LDX]       = "ldx",
        [BPF_LDX_B]     = "ldxb",
        [BPF_JMP_JA]    = "ja",
        [BPF_JMP_JEQ]   = "jeq",
        [BPF_JMP_JGT]   = "jgt",
        [BPF_JMP_JGE]   = "jge",
        [BPF_JMP_JSET]  = "jset",
        [BPF_ALU_ADD]   = "add",
        [BPF_ALU_SUB]   = "sub",
        [BPF_ALU_MUL]   = "mul",
        [BPF_ALU_DIV]   = "div",
        [BPF_ALU_MOD]   = "mod",
        [BPF_ALU_NEG]   = "neg",
        [BPF_ALU_AND]   = "and",
        [BPF_ALU_OR]    = "or",
        [BPF_ALU_XOR]   = "xor",
        [BPF_ALU_LSH]   = "lsh",
        [BPF_ALU_RSH]   = "rsh",
        [BPF_MISC_TAX]  = "tax",
        [BPF_MISC_TXA]  = "txa",
        [BPF_RET]       = "ret",
};

static void bpf_disasm(const struct sock_filter f, unsigned int i)
{
	const char *op, *fmt;
	int val = f.k;
	char buf[256];

	switch (f.code) {
	case BPF_RET | BPF_K:
		op = op_table[BPF_RET];
		fmt = "#%#x";
		break;
	case BPF_RET | BPF_A:
		op = op_table[BPF_RET];
		fmt = "a";
		break;
	case BPF_RET | BPF_X:
		op = op_table[BPF_RET];
		fmt = "x";
		break;
	case BPF_MISC_TAX:
		op = op_table[BPF_MISC_TAX];
		fmt = "";
		break;
	case BPF_MISC_TXA:
		op = op_table[BPF_MISC_TXA];
		fmt = "";
		break;
	case BPF_ST:
		op = op_table[BPF_ST];
		fmt = "M[%d]";
		break;
	case BPF_STX:
		op = op_table[BPF_STX];
		fmt = "M[%d]";
		break;
	case BPF_LD_W | BPF_ABS:
		op = op_table[BPF_LD_W];
		fmt = "[%d]";
		break;
	case BPF_LD_H | BPF_ABS:
		op = op_table[BPF_LD_H];
		fmt = "[%d]";
		break;
	case BPF_LD_B | BPF_ABS:
		op = op_table[BPF_LD_B];
		fmt = "[%d]";
		break;
	case BPF_LD_W | BPF_LEN:
		op = op_table[BPF_LD_W];
		fmt = "#len";
		break;
	case BPF_LD_W | BPF_IND:
		op = op_table[BPF_LD_W];
		fmt = "[x+%d]";
		break;
	case BPF_LD_H | BPF_IND:
		op = op_table[BPF_LD_H];
		fmt = "[x+%d]";
		break;
	case BPF_LD_B | BPF_IND:
		op = op_table[BPF_LD_B];
		fmt = "[x+%d]";
		break;
	case BPF_LD | BPF_IMM:
		op = op_table[BPF_LD_W];
		fmt = "#%#x";
		break;
	case BPF_LDX | BPF_IMM:
		op = op_table[BPF_LDX];
		fmt = "#%#x";
		break;
	case BPF_LDX_B | BPF_MSH:
		op = op_table[BPF_LDX_B];
		fmt = "4*([%d]&0xf)";
		break;
	case BPF_LD | BPF_MEM:
		op = op_table[BPF_LD_W];
		fmt = "M[%d]";
		break;
	case BPF_LDX | BPF_MEM:
		op = op_table[BPF_LDX];
		fmt = "M[%d]";
		break;
	case BPF_JMP_JA:
		op = op_table[BPF_JMP_JA];
		fmt = "%d";
		val = i + 1 + f.k;
		break;
	case BPF_JMP_JGT | BPF_X:
		op = op_table[BPF_JMP_JGT];
		fmt = "x";
		break;
	case BPF_JMP_JGT | BPF_K:
		op = op_table[BPF_JMP_JGT];
		fmt = "#%#x";
		break;
	case BPF_JMP_JGE | BPF_X:
		op = op_table[BPF_JMP_JGE];
		fmt = "x";
		break;
	case BPF_JMP_JGE | BPF_K:
		op = op_table[BPF_JMP_JGE];
		fmt = "#%#x";
		break;
	case BPF_JMP_JEQ | BPF_X:
		op = op_table[BPF_JMP_JEQ];
		fmt = "x";
		break;
	case BPF_JMP_JEQ | BPF_K:
		op = op_table[BPF_JMP_JEQ];
		fmt = "#%#x";
		break;
	case BPF_JMP_JSET | BPF_X:
		op = op_table[BPF_JMP_JSET];
		fmt = "x";
		break;
	case BPF_JMP_JSET | BPF_K:
		op = op_table[BPF_JMP_JSET];
		fmt = "#%#x";
		break;
	case BPF_ALU_NEG:
		op = op_table[BPF_ALU_NEG];
		fmt = "";
		break;
	case BPF_ALU_LSH | BPF_X:
		op = op_table[BPF_ALU_LSH];
		fmt = "x";
		break;
	case BPF_ALU_LSH | BPF_K:
		op = op_table[BPF_ALU_LSH];
		fmt = "#%d";
		break;
	case BPF_ALU_RSH | BPF_X:
		op = op_table[BPF_ALU_RSH];
		fmt = "x";
		break;
	case BPF_ALU_RSH | BPF_K:
		op = op_table[BPF_ALU_RSH];
		fmt = "#%d";
		break;
	case BPF_ALU_ADD | BPF_X:
		op = op_table[BPF_ALU_ADD];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_K:
		op = op_table[BPF_ALU_ADD];
		fmt = "#%d";
		break;
	case BPF_ALU_SUB | BPF_X:
		op = op_table[BPF_ALU_SUB];
		fmt = "x";
		break;
	case BPF_ALU_SUB | BPF_K:
		op = op_table[BPF_ALU_SUB];
		fmt = "#%d";
		break;
	case BPF_ALU_MUL | BPF_X:
		op = op_table[BPF_ALU_MUL];
		fmt = "x";
		break;
	case BPF_ALU_MUL | BPF_K:
		op = op_table[BPF_ALU_MUL];
		fmt = "#%d";
		break;
	case BPF_ALU_DIV | BPF_X:
		op = op_table[BPF_ALU_DIV];
		fmt = "x";
		break;
	case BPF_ALU_DIV | BPF_K:
		op = op_table[BPF_ALU_DIV];
		fmt = "#%d";
		break;
	case BPF_ALU_MOD | BPF_X:
		op = op_table[BPF_ALU_MOD];
		fmt = "x";
		break;
	case BPF_ALU_MOD | BPF_K:
		op = op_table[BPF_ALU_MOD];
		fmt = "#%d";
		break;
	case BPF_ALU_AND | BPF_X:
		op = op_table[BPF_ALU_AND];
		fmt = "x";
		break;
	case BPF_ALU_AND | BPF_K:
		op = op_table[BPF_ALU_AND];
		fmt = "#%#x";
		break;
	case BPF_ALU_OR | BPF_X:
		op = op_table[BPF_ALU_OR];
		fmt = "x";
		break;
	case BPF_ALU_OR | BPF_K:
		op = op_table[BPF_ALU_OR];
		fmt = "#%#x";
		break;
	case BPF_ALU_XOR | BPF_X:
		op = op_table[BPF_ALU_XOR];
		fmt = "x";
		break;
	case BPF_ALU_XOR | BPF_K:
		op = op_table[BPF_ALU_XOR];
		fmt = "#%#x";
		break;
	default:
		op = "nosup";
		fmt = "%#x";
		val = f.code;
		break;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), fmt, val);
	buf[sizeof(buf) - 1] = 0;

	if ((BPF_CLASS(f.code) == BPF_JMP && BPF_OP(f.code) != BPF_JA)) {
		printf("l%d:\t%s %s, l%d, l%d\n", i, op, buf,
			  i + 1 + f.jt, i + 1 + f.jf);
	} else {
		printf("l%d:\t%s %s\n", i, op, buf);
	}

}

static void bpf_disasm_all(const struct sock_filter *f, unsigned int len)
{
	unsigned int i;
	for (i = 0; i < len; i++)
		bpf_disasm(f[i], i);
}

int main(int argc, char **argv)
{
        struct sock_filter *filter;
        size_t fd, n;

        if (argc < 2) {
                perror("missing input file");
                exit(EXIT_FAILURE);
        }
	filter = calloc(SIZE_FILTER, sizeof(struct sock_filter));
        fd = open(argv[1], O_CLOEXEC | O_RDONLY);

        n = read(fd, filter, sizeof(struct sock_filter)*SIZE_FILTER);
        close(fd);
	printf("Read %ld entries\n", n/sizeof(struct sock_filter));
	bpf_disasm_all(filter, n/sizeof(struct sock_filter));
	free(filter);
        return 0;
}


#!/bin/sh -eu
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
#
# filter.sh - Build binary-search tree BPF program with SECCOMP_RET_USER_NOTIF
#
# Copyright (c) 2022 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

TMP="$(mktemp)"
IN="${@}"
OUT_NUMBERS="numbers.h"

HEADER_NUMBERS="/* This file was automatically generated by $(basename ${0}) */

struct syscall_numbers {
        char name[1024];
        long number;
};

struct syscall_numbers numbers[] = {"

FOOTER_NUMBERS="};"

syscalls=(
	"accept"
	"bind"
	"connect"
	"getpeername"
	"getsockname"
	"getsockopt"
	"listen"
	"mount"
	"openat"
	"recvfrom"
	"recvmmsg"
	"recvmsg"
	"sendmmsg"
	"sendmsg"
	"sendto"
	"setsockopt"
	"shutdown"
	"socket"
	"socketpair"
)

printf '%s\n' "${HEADER_NUMBERS}" > "${OUT_NUMBERS}"
# syscall_nr - Get syscall number from compiler, also note in numbers.h
__in="$(printf "#include <asm-generic/unistd.h>\n#include <sys/syscall.h>\n__NR_%s" ${syscalls[@]})"
__out="$(echo "${__in}" |cc -E -xc - -o - |sed -n '/\#.*$/!p'| sed '/^$/d')"
# Output might be in the form "(x + y)" (seen on armv6l, armv7l)
#__out="$(eval echo $((${__out})))"
#echo "${__out}"

awk  -v AS="${syscalls[*]}" -v BS="${__out[*]}" \
'BEGIN { MAX=split(AS,a, / /); split(BS,b, / /);
for (x = 1; x <= MAX; x++)
         { printf "\t{\"%s\",\t%d},\n", a[x], b[x] }
 }' >> "${OUT_NUMBERS}"

printf '%s\n' "${FOOTER_NUMBERS}" >> "${OUT_NUMBERS}"

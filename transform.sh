#!/bin/sh -eu
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# SEITAN - Syscall Expressive Interpreter, Transformer and Notifier
#
# transform.sh - Build syscall transformation table headers
#
# Copyright (c) 2022 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

TMP="$(mktemp)"
IN="${@}"
OUT="transform.h"

HEADER="/* This file was automatically generated by $(basename ${0}) */

struct table {
	int type;
	long number;
	char arg[1024][6];
};"

# Prefix for each profile
PRE='
struct table table_@PROFILE@[] = {'

# Suffix for each profile
POST='};
'

# cleanup() - Remove temporary file if it exists
cleanup() {
	rm -f "${TMP}"
}
trap "cleanup" EXIT

# sub() - Substitute in-place file line with processed template line
# $1:	Line number
# $2:	Template name (variable name)
# $@:	Replacement for @KEY@ in the form KEY:value
sub() {
	IFS=
	__line_no="${1}"
	__template="$(eval printf '%s' "\${${2}}")"
	shift; shift

	sed -i "${__line_no}s#.*#${__template}#" "${TMP}"

	IFS=' '
	for __def in ${@}; do
		__key="@${__def%%:*}@"
		__value="${__def#*:}"
		sed -i "${__line_no}s/${__key}/${__value}/" "${TMP}"
	done
	unset IFS
}

# finish() - Finalise header file from temporary files with prefix and suffix
# $1:	Variable name of prefix
# $@:	Replacements for prefix variable
finish() {
	IFS=
	__out="$(eval printf '%s' "\${${1}}")"
	shift

	IFS=' '
	for __def in ${@}; do
		__key="@${__def%%:*}@"
		__value="${__def#*:}"
		__out="$(printf '%s' "${__out}" | sed "s#${__key}#${__value}#")"
	done

	printf '%s\n' "${__out}" >> "${OUT}"
	cat "${TMP}" >> "${OUT}"
	rm "${TMP}"
	printf '%s' "${POST}" >> "${OUT}"
	unset IFS
}

# syscall_nr - Get syscall number from compiler
# $1:	Name of syscall
syscall_nr() {
	__in="$(printf "#include <asm-generic/unistd.h>\n#include <sys/syscall.h>\n__NR_%s" ${1})"
	__out="$(echo "${__in}" | cc -E -xc - -o - | tail -1)"
	[ "${__out}" = "__NR_$1" ] && return 1

	# Output might be in the form "(x + y)" (seen on armv6l, armv7l)
	__out="$(eval echo $((${__out})))"
	echo "${__out}"
}

filter() {
	__filtered=
	for __c in ${@}; do
		__arch_match=0
		case ${__c} in
		*:*)
			case ${__c} in
			$(uname -m):*)
				__arch_match=1
				__c=${__c##*:}
				;;
			esac
			;;
		*)
			__arch_match=1
			;;
		esac
		[ ${__arch_match} -eq 0 ] && continue

		IFS='| '
		__found=0
		for __name in ${__c}; do
			syscall_nr "${__name}" >/dev/null && __found=1 && break
		done
		unset IFS

		if [ ${__found} -eq 0 ]; then
			echo
			echo "Warning: no syscall number for ${__c}" >&2
			echo "  none of these syscalls will be allowed" >&2
			continue
		fi

		__filtered="${__filtered} ${__name}"
	done

	echo "${__filtered}" | tr ' ' '\n' | sort -u
}

printf '%s\n' "${HEADER}" > "${OUT}"
__profiles="${IN}"
for __p in ${__profiles}; do
	IFS='
'
	for __l in $(grep "^[a-z].*" "${__p}" | tr -s '\t'); do
		unset IFS
		__syscall_token="$(echo "${__l}" | cut -f1)"
		__type_token="$(echo "${__l}" | cut -f2)"
		__arg1_token="$(echo "${__l}" | cut -f3)"
		__arg2_token="$(echo "${__l}" | cut -f4)"
		__arg3_token="$(echo "${__l}" | cut -f5)"
		__arg4_token="$(echo "${__l}" | cut -f6)"
		__arg5_token="$(echo "${__l}" | cut -f7)"
		__arg6_token="$(echo "${__l}" | cut -f8)"

		__syscall_nr="$(syscall_nr "${__syscall_token}")"
		__type_enum="$(echo ${__type_token} | tr [a-z] [A-Z])"

		printf "\t{ %i, %s, \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", },\n" \
			${__syscall_nr} "${__type_enum}" \
			"${__arg1_token}" "${__arg2_token}" "${__arg3_token}" \
			"${__arg4_token}" "${__arg5_token}" "${__arg6_token}" \
			>> "${TMP}"
	IFS='
'
	done
	finish PRE "PROFILE:${__p}"
done

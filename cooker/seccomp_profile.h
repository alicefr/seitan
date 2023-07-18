/* SPDX-License-Identifier: GPL-2.0-or-later
* Copyright 2023 Red Hat GmbH
* Author: Alice Frosi <afrosi@redhat.com>
*/

#ifndef SCMP_PROFILE_H_
#define SCMP_PROFILE_H_

#include <linux/limits.h>
#include <stdint.h>
#include <unistd.h>

#include "parson.h"
#include "util.h"
#include "cooker.h"
#include "gluten.h"

#define STRING_MAX 2000
#define COMMENT_MAX 1000
/* TODO define it in a common place */
#define SYSCALL_MAX 512
#define MAX_SUB_ARCHES 3
#define check_JSON_status(status)                          \
	do {                                               \
		if (status == JSONFailure)                 \
			die("failing parsing JSON value"); \
	} while (0)
/*
* Definition for the OCI Seccomp Specification:
* https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp
*/
extern const char *scmp_act_str[];

enum scmp_act_type {
	ACT_KILLTHREAD,
	ACT_TRAP,
	ACT_ERRNO,
	ACT_TRACE,
	ACT_ALLOW,
	ACT_LOG,
	ACT_NOTIFY,
};

// Define operators for syscall arguments in Seccomp
extern const char *scmp_op_str[];

enum scmp_op_type {
	OP_NO_CHECK,
	OP_NOTEQUAL,
	OP_LESSTHAN,
	OP_LESSEQUAL,
	OP_EQUALTO,
	OP_GREATEREQUAL,
	OP_GREATERTHAN,
	OP_MASKEDEQUAL,
};

// Arg used for matching specific syscall arguments in Seccomp
struct scmp_arg {
	bool set;
	uint32_t index;
	uint64_t value;
	uint64_t valueTwo;
	enum scmp_op_type op;
};

extern const char *arch_str[];

enum arch_type {
	ARCH_NATIVE = 0,
	ARCH_X86,
	ARCH_X86_64,
	ARCH_X32,
	ARCH_ARM,
	ARCH_AARCH64,
	ARCH_MIPS,
	ARCH_MIPS64,
	ARCH_MIPS64N2,
	ARCH_MIPSEL,
	ARCH_MIPSEL6,
	ARCH_MIPSEL6N32,
	ARCH_PPC,
	ARCH_PPC64,
	ARCH_PPC64LE,
	ARCH_S390,
	ARCH_S390X,
	ARCH_PARISC,
	ARCH_PARISC6,
	ARCH_RISCV64,
	ARCH_MAX = ARCH_RISCV64,
};

// Architecture is used to represent a specific architecture
// and its sub-architectures
struct architecture {
	enum arch_type arch;
	enum arch_type subArches[MAX_SUB_ARCHES];
};

enum caps_type {
	CAP_CHOWN = 0,
	CAP_DAC_OVERRIDE = 1,
	CAP_DAC_READ_SEARCH = 2,
	CAP_FOWNER = 3,
	CAP_FSETID = 4,
	CAP_KILL = 5,
	CAP_SETGID = 6,
	CAP_SETUID = 7,
	CAP_SETPCAP = 8,
	CAP_LINUX_IMMUTABLE = 9,
	CAP_NET_BIND_SERVICE = 10,
	CAP_NET_BROADCAST = 11,
	CAP_NET_ADMIN = 12,
	CAP_NET_RAW = 13,
	CAP_IPC_LOCK = 14,
	CAP_IPC_OWNER = 15,
	CAP_SYS_MODULE = 16,
	CAP_SYS_RAWIO = 17,
	CAP_SYS_CHROOT = 18,
	CAP_SYS_PTRACE = 19,
	CAP_SYS_PACCT = 20,
	CAP_SYS_ADMIN = 21,
	CAP_SYS_BOOT = 22,
	CAP_SYS_NICE = 23,
	CAP_SYS_RESOURCE = 24,
	CAP_SYS_TIME = 25,
	CAP_SYS_TTY_CONFIG = 26,
	CAP_MKNOD = 27,
	CAP_LEASE = 28,
	CAP_AUDIT_WRITE = 29,
	CAP_AUDIT_CONTROL = 30,
	CAP_SETFCAP = 31,
	CAP_MAC_OVERRIDE = 32,
	CAP_MAC_ADMIN = 33,
	CAP_SYSLOG = 34,
	CAP_WAKE_ALARM = 35,
	CAP_BLOCK_SUSPEND = 36,
	CAP_AUDIT_READ = 37,
	CAP_PERFMON = 38,
	CAP_BPF = 39,
	CAP_CHECKPOINT_RESTORE = 40,
	CAP_LAST_CAP = 41,
	CAPS_MAX = CAP_LAST_CAP,
};

// Filter is used to conditionally apply Seccomp rules
struct scmp_filter {
	enum caps_type caps[CAPS_MAX];
	enum arch_type arches[ARCH_MAX];
};

extern const char *scmp_filter_str[];

enum scmp_filter_type {
	SCMP_FILT_FLAG_TSYNC,
	SCMP_FILT_FLAG_LOG,
	SCMP_FILT_FLAG_SPEC_ALLOW,
	SCMP_FILT_FLAG_WAIT_KILLABLE_RECV,
	SCMP_FILT_FLAG_MAX = SCMP_FILT_FLAG_WAIT_KILLABLE_RECV,
};

// Syscall is used to match a group of syscalls in Seccomp
struct syscall {
	/* here we use a single syscall per entry*/
	char names[STRING_MAX];
	enum scmp_act_type action;
	struct scmp_arg args[6];
	char comment[COMMENT_MAX];
	enum scmp_filter_type includes;
	enum scmp_filter_type excludes;
	char err[STRING_MAX];
};

// Seccomp represents the config for a seccomp profile for syscall restriction.
struct seccomp {
	enum scmp_act_type default_action;

	char defaultErrno[STRING_MAX];

	// Architectures is kept to maintain backward compatibility with the old
	// seccomp profile.
	enum arch_type architectures[ARCH_MAX];
	struct architecture archMap[ARCH_MAX];
	struct syscall syscalls[SYSCALL_MAX];
	enum scmp_filter_type flags[SCMP_FILT_FLAG_MAX];
	char listenerPath[PATH_MAX];
	char listenerMetadata[PATH_MAX];
};

void scmp_profile_init();
void scmp_profile_notify(const char *name);
void scmp_profile_add_check(int index, union value v, union value mask,
			    enum op_cmp_type cmp);
void scmp_profile_write(const char *file);
void scmp_profile_flush_args();
#endif

// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/emit.c - Generate gluten (bytecode) instructions and read-only data
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Alice Frosi <afrosi@redhat.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "seccomp_profile.h"

static struct seccomp scmp_profile;
static unsigned int counter;
static unsigned int count_args;
static JSON_Object *root_obj;
static JSON_Value *root;
static bool ignore_syscall;

const char *scmp_act_str[] = {
	"SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP",  "SCMP_ACT_ERRNO",
	"SCMP_ACT_TRACE",	"SCMP_ACT_ALLOW", "SCMP_ACT_LOG",
	"SCMP_ACT_NOTIFY",
};

const char *scmp_op_str[] = {
	"",
	"SCMP_CMP_NE",
	"SCMP_CMP_LT",
	"SCMP_CMP_LE",
	"SCMP_CMP_EQ",
	"SCMP_CMP_GE",
	"SCMP_CMP_GT",
	"SCMP_CMP_MASKED_EQ",
};

const char *arch_str[] = {
	"SCMP_ARCH_NATIVE",   "SCMP_ARCH_X86",	    "SCMP_ARCH_X86_64",
	"SCMP_ARCH_X32",      "SCMP_ARCH_ARM",	    "SCMP_ARCH_AARCH64",
	"SCMP_ARCH_MIPS",     "SCMP_ARCH_MIPS64",   "SCMP_ARCH_MIPS64N32",
	"SCMP_ARCH_MIPSEL",   "SCMP_ARCH_MIPSEL64", "SCMP_ARCH_MIPSEL64N32",
	"SCMP_ARCH_PPC",      "SCMP_ARCH_PPC64",    "SCMP_ARCH_PPC64LE",
	"SCMP_ARCH_S390",     "SCMP_ARCH_S390X",    "SCMP_ARCH_PARISC",
	"SCMP_ARCH_PARISC64", "SCMP_ARCH_RISCV64",
};

const char *scmp_filter_str[] = {
	"SECCOMP_FILTER_FLAG_TSYNC",
	"SECCOMP_FILTER_FLAG_LOG",
	"SECCOMP_FILTER_FLAG_SPEC_ALLOW",
	"SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV",
};

// TODO: decide defaults for when the original profile isn't definied
static void set_defaults_scmp_profile()
{
	scmp_profile.default_action = ACT_ERRNO;
	die("Not implemented yet");
}

static void parse_orig_scmp_profile(char *path)
{
	debug("Use %s as base for the generated seccomp profile", path);
	root = json_parse_file(path);
	if (root == NULL)
		die("  failed parsing JSON seccomp profile: %s", path);
}

/**
 * is_scmp_notify_set - Verify if one of the syscall entries has the SCMP_NOTIFY
 * action enabled
 *
 */
static bool is_scmp_notify_set(JSON_Array *syscalls)
{
	const char *action;
	JSON_Object *obj;
	unsigned int i;

	for (i = 0; i < json_array_get_count(syscalls); i++) {
		if (((obj = json_array_get_object(syscalls, i)) == NULL) ||
		    ((action = json_object_get_string(obj, "action")) == NULL))
			continue;
		if (strcmp(action, scmp_act_str[ACT_NOTIFY]) == 0)
			return true;
	}
	return false;
}

void scmp_profile_init(char *path)
{
	JSON_Array *syscalls;
	counter = 0;
	count_args = 0;

	if (path == NULL) {
		root = json_value_init_object();
		debug("Set defaults for the seccomp profile");
		set_defaults_scmp_profile();
	} else {
		parse_orig_scmp_profile(path);
	}
	if ((root_obj = json_value_get_object(root)) == NULL)
		die("  failed serialize JSON");

	if ((syscalls = json_object_get_array(root_obj, "syscalls")) == NULL)
		return;
	if (is_scmp_notify_set(syscalls))
		die("  the use of multiple seccomp notifiers isn't supported");
}

static bool is_syscall_present(const char *name)
{
	if (name == NULL)
		return false;
	for (unsigned int i = 0; i < counter; i++)
		if (strcmp(scmp_profile.syscalls[i].names, name) == 0)
			return true;

	return false;
}

void scmp_profile_notify(const char *name)
{
	ignore_syscall = false;
	if (is_syscall_present(name)) {
		ignore_syscall = true;
		return;
	}
	debug("  #%u add syscall %s to seccomp profile", counter, name);
	strcpy(scmp_profile.syscalls[counter].names, name);
	scmp_profile.syscalls[counter].action = ACT_NOTIFY;
}

void scmp_profile_add_check(int index, union value v, union value mask,
			    enum op_cmp_type cmp)
{
	char *name = scmp_profile.syscalls[counter].names;
	struct scmp_arg *arg;

	if (count_args > 5)
		die("  too many arguments for the syscall entry %d:%s", counter,
		    name);
	debug("  #%u add arg to syscall %s to seccomp profile", count_args);
	arg = &scmp_profile.syscalls[counter].args[count_args];
	arg->index = index;
	arg->value = v.v_num;
	arg->set = true;
	if (mask.v_num) {
		arg->valueTwo = mask.v_num;
		arg->op = OP_MASKEDEQUAL;
		return;
	}

	// TODO: check if also the other cmp operations are inverted in cooker
	switch (cmp) {
	case CMP_NE:
		arg->op = OP_EQUALTO;
		break;
	case CMP_EQ:
		arg->op = OP_NOTEQUAL;
		break;
	case CMP_LE:
		arg->op = OP_LESSEQUAL;
		break;
	case CMP_LT:
		arg->op = OP_LESSTHAN;
		break;
	case CMP_GE:
		arg->op = OP_GREATEREQUAL;
		break;
	case CMP_GT:
		arg->op = OP_GREATERTHAN;
		break;
	default:
		die("  operation not recognized");
		break;
	}
}

void scmp_profile_flush_args()
{
	if (ignore_syscall)
		return;
	debug("  flush args for syscall %s",
	      scmp_profile.syscalls[counter].names);
	counter++;
	count_args = 0;
}

static void json_append_syscall(JSON_Array *syscalls, struct syscall *syscall)
{
	JSON_Value *val = json_value_init_object();
	JSON_Object *obj = json_value_get_object(val);
	JSON_Value *arg = json_value_init_object();
	JSON_Object *arg_obj = json_value_get_object(arg);
	JSON_Array *names_array;
	JSON_Array *args_array;

	json_object_set_value(obj, "names", json_value_init_array());
	json_object_set_value(obj, "args", json_value_init_array());
	names_array = json_object_get_array(obj, "names");
	;
	args_array = json_object_get_array(obj, "args");
	;
	check_JSON_status(json_object_set_string(obj, "action",
						 scmp_act_str[ACT_NOTIFY]));
	check_JSON_status(
		json_array_append_string(names_array, &syscall->names[0]));
	for (unsigned int i = 0; i < 6; i++) {
		if (!syscall->args[i].set)
			continue;
		check_JSON_status(json_object_set_number(
			arg_obj, "index", syscall->args[i].index));
		check_JSON_status(json_object_set_number(
			arg_obj, "value", syscall->args[i].value));
		check_JSON_status(json_object_set_number(
			arg_obj, "valueTwo", syscall->args[i].valueTwo));
		check_JSON_status(json_object_set_string(
			arg_obj, "op", scmp_op_str[syscall->args[i].op]));
		check_JSON_status(json_array_append_value(args_array, arg));
		debug(" added args for syscall %s %d: ", syscall->names, i,
		      syscall->args[i].value, syscall->args[i].valueTwo,
		      scmp_op_str[syscall->args[i].op]);
	}
	json_array_append_value(syscalls, val);
}

/**
 * remove_existing_syscall() - Remove the syscall entry name from the list where
 * the syscall is listed as allowed and without parameters.
 * Eg. if in the original seccomp profile with the 'connect' syscall:
 *   "syscalls": [
 *                   {
 *                        "names": [ ..
 *	                           "connect",
 *	                           ..
 *                        "action": "SCMP_ACT_ALLOW",
 *                        "args": [],
 *                   }
 *
 */
static void remove_existing_syscall(JSON_Array *syscalls, char *name)
{
	const char *curr_syscall, *action;
	JSON_Array *names, *args;
	unsigned int i, k;
	JSON_Object *obj;

	for (i = 0; i < json_array_get_count(syscalls); i++) {
		if (((obj = json_array_get_object(syscalls, i)) == NULL) ||
		    ((names = json_object_get_array(obj, "names")) == NULL) ||
		    ((args = json_object_get_array(obj, "args")) == NULL) ||
		    ((action = json_object_get_string(obj, "action")) == NULL))
			continue;
		if ((strcmp(action, scmp_act_str[ACT_ALLOW]) != 0) ||
		    (json_array_get_count(args) > 0))
			continue;
		for (k = 0; k < json_array_get_count(names); k++) {
			curr_syscall = json_array_get_string(names, k);
			if (curr_syscall == NULL)
				die("  empty syscall name");
			if (strcmp(curr_syscall, name) == 0) {
				debug("  remove %s as duplicate at %d",
				      curr_syscall, k);
				json_array_remove(names, k);
			}
		}
	}
}

static void json_serialize_syscalls()
{
	JSON_Array *syscalls;
	unsigned int i;

	if ((syscalls = json_object_get_array(root_obj, "syscalls")) == NULL) {
		json_object_set_value(root_obj, "syscalls",
				      json_value_init_array());
		syscalls = json_object_get_array(root_obj, "syscalls");
	}

	for (i = 0; i < counter; i++) {
		remove_existing_syscall(syscalls,
					&scmp_profile.syscalls[i].names[0]);
		// Create syscall entry for the notify
		json_append_syscall(syscalls, &scmp_profile.syscalls[i]);
	}
}

void scmp_profile_write(const char *file)
{
	debug("Write seccomp profile to %s", file);
	json_serialize_syscalls();
	json_serialize_to_file_pretty(root, file);

	json_value_free(root);

	return;
}

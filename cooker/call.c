// SPDX-License-Identifier: GPL-2.0-or-later

/* seitan - Syscall Expressive Interpreter, Transformer and Notifier
 *
 * cooker/call.c - Parse "call" rules from JSON recipe into bytecode
 *
 * Copyright 2023 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "parson.h"
#include "calls.h"
#include "cooker.h"
#include "gluten.h"
#include "emit.h"
#include "parse.h"
#include "util.h"

static bool is_metadata_obj(JSON_Object *metadata)
{
	if (!metadata)
		return false;
	return ((!json_object_get_string(metadata, "caller")) ||
		(!json_object_get_string(metadata, "set")) ||
		(!json_object_get_string(metadata, "get")));
}

/* TODO: refactor and simplify this horrible function */
static union value parse_metadata(struct gluten_ctx *g, struct field *f,
				  struct gluten_offset **base_offset,
				  struct gluten_offset offset,
				  JSON_Object *metadata, bool dry_run, bool add)
{
	const char *tag;
	size_t count = 0;
	union value v = { .v_num = 0 };

	if ((tag = json_object_get_string(metadata, "caller"))) {
		debug("    args reference value at runtime '%s' with metadata %s", tag, tag);
		(*base_offset)->type = OFFSET_METADATA;
		if (!strcmp(tag, "uid")) {
			(*base_offset)->offset = UID_TARGET;
		} else if (!strcmp(tag, "gid")) {
			(*base_offset)->offset = GID_TARGET;
		} else if (!strcmp(tag, "pid")) {
			(*base_offset)->offset = PID_TARGET;
		} else {
			die("    unrecognized metadata tag: %s", tag);
		}
		return v;
	}

	if ((tag = json_object_get_string(metadata, "set"))) {
		count++;
		debug("    setting tag reference (post) '%s'", tag);

		if (!dry_run)
			gluten_add_tag_post(g, tag, offset);

		if (f->flags & RBUF)
			return v;
	}

	if ((tag = json_object_get_string(metadata, "get"))) {
		struct gluten_offset tag_offset;

		count++;
		debug("    getting tag reference '%s'", tag);

		/* TODO: Check type */
		tag_offset = gluten_get_tag(g, tag);
		if (tag_offset.type == OFFSET_NULL)
			die("   tag not found");

		if ((*base_offset)->type == OFFSET_NULL) {
			**base_offset = tag_offset;
		} else if (f->flags & MASK || add) {
			emit_bitwise(g, f->type, BITWISE_OR, offset, offset,
				     tag_offset);
		} else {
			emit_copy_field(g, f, offset, tag_offset);
		}
	}

	if (json_object_get_count(metadata) > count)
		die("stray object in tag reference");

	if (!count)
		die("invalid tag specification");

	return v;
}

/**

struct syscall_desc {
	unsigned nr:9;

	unsigned arg_count:3;
	unsigned has_ret:1;

	unsigned arg_deref:6;

	struct gluten_offset data[];
};

match: "tag": "x" -- meaning "set"
call: "tag": { "set": "x", "get": "y" }

Examples of arguments:
- INT: 2		write 2 in ro_data, and pointer to it
				parse_arg() passes null offset
				parse_field() passes back ro_data offset

- INT *: 2		write 2 in ro_data (using size), and pointer to it
  no flags or tags		parse_arg() passes ro_data offset

- INT *: 2		- write 2 in ro_data at x
  COPY_ON_CALL		- emit op_copy from x to y
  or "set" tag		- write pointer to y
				parse_arg() passes data offset

- INT: "get" <tag>	write pointer to tag
				parse_arg() passes null offset
				parse_field() gives back ro_data or data offset

- INT *: "get" <tag>	write pointer to tag
  no COPY_ON_CALL		parse_arg() passes null offset
				parse_field() gives back data offset

- STRING: abcd		write abcd to ro_data (using size), and pointer to it
				parse_arg() passes ro_data offset

- STRUCT: 1, 2		write struct to ro_data, and pointer to it
				parse_arg() passes ro_data offset

- STRUCT: "get" <tag>	write pointer to tag
				parse_arg() passes null offset
				parse_field() gives back data offset

- STRUCT: <tag>, 2	- write 2 to ro_data at x
			- allocate rw_data at y
			- emit op_copy from tag to y
			- emit op_copy from x to y + offset of "2"
			- write pointer to y
				parse_arg() passes data offset
 */

static union value parse_field(struct gluten_ctx *g, struct arg *args,
			       struct gluten_offset *base_offset,
			       int index, struct field *f, JSON_Value *jvalue,
			       bool dry_run, bool add)
{
	struct gluten_offset offset = *base_offset;
	union value v = { .v_num = 0 };
	JSON_Object *tmp1;
	struct field *f_inner;
	JSON_Value *sel;

	if (f->name)
		debug("    parsing field name %s", f->name);

	if (offset.type != OFFSET_NULL)
		offset.offset += f->offset;
	if (!(tmp1 = json_value_get_object(jvalue)) && is_metadata_obj(tmp1))
		v = parse_metadata(g, f, &base_offset, offset, tmp1, dry_run,
				   add);
	if (v.v_num == 0)
		return v;

	if (!jvalue && !(f->flags & SIZE))
		return v;

	switch (f->type) {
	case USHORT:
	case INT:
	case LONG:
	case U32:
	case GNU_DEV_MAJOR:
	case GNU_DEV_MINOR:
		if (json_value_get_type(jvalue) == JSONArray) {
			JSON_Array *array = json_value_get_array(jvalue);
			unsigned i;

			if (!(f->flags & FLAGS))
				die("multiple values for non-FLAGS argument");

			for (i = 0; i < json_array_get_count(array); i++) {
				jvalue = json_array_get_value(array, i);
				v.v_num |= value_get_num(f->desc.d_num, jvalue);
			}
		} else if (f->flags == SIZE) {
			v.v_num = value_get_size(g, f->desc.d_size);
		} else {
			v.v_num = value_get_num(f->desc.d_num, jvalue);
		}

		if (dry_run)
			break;

		if (base_offset->type == OFFSET_NULL) {
			*base_offset = gluten_ro_alloc_type(g, U64);
			emit_data_at(g, *base_offset, f->type, &v);
		} else if (add) {
			emit_data_or(g, offset, f->type, &v);
		} else {
			emit_data_at(g, offset, f->type, &v);
		}

		break;
	case SELECT:
		f_inner = f->desc.d_select->field;

		if ((tmp1 = json_value_get_object(jvalue))) {
			if (!(sel = json_object_get_value(tmp1, f_inner->name)))
				die("   no selector for '%s'", f_inner->name);
		} else {
			sel = jvalue;
		}

		v = parse_field(g, args, &offset, index, f_inner, sel,
				false, false);

		f = select_field(g, index, f->desc.d_select, v);
		if (f) {
			parse_field(g, args, &offset, index, f, jvalue,
				    false, add);
		}
		break;
	case STRING:
		if (dry_run)
			break;

		if ((v.v_str = json_value_get_string(jvalue)) == NULL)
			die("   failed parsing string for %s", json_serialize_to_string(jvalue));
		if (strlen(v.v_str) + 1 > f->size)
			die("   string %s too long for field", v.v_str);

		emit_data_at(g, offset, f->type, &v);
		break;
	case STRUCT:
		for (f_inner = f->desc.d_struct; f_inner->name; f_inner++) {
			struct gluten_offset struct_start = offset;
			JSON_Value *f_value;

			tmp1 = json_value_get_object(jvalue);
			f_value = json_object_get_value(tmp1, f_inner->name);
			if (!f_value)
				continue;
			parse_field(g, args, &struct_start, index, f_inner,
				    f_value, false, add);
		}
		break;
	default:
		;
	}

	return v;
}

bool arg_needs_temp(struct field *f, int pos, JSON_Value *jvalue,
		    bool *top_level_tag, int level)
{
	struct gluten_offset unused = { .type = OFFSET_NULL, .offset = 0 };
	union value v = { .v_num = 0 };
	struct field *f_inner;
	JSON_Object *tmp;
	JSON_Value *sel;

	if (f->flags & COPY_ON_CALL)
		return true;

	if (f->flags & SIZE)
		return false;

	if (json_value_get_type(jvalue) == JSONObject &&
	    (tmp = json_value_get_object(jvalue))) {
		if (json_object_get_string(tmp, "set"))
			return true;

		if (level)
			return true;

		if (top_level_tag)
			*top_level_tag = true;

		return false;
	}

	switch (f->type) {
	case USHORT:
	case INT:
	case LONG:
	case U32:
		return false;
	case GNU_DEV_MAJOR:
	case GNU_DEV_MINOR:
		return true;
	case SELECT:
		f_inner = f->desc.d_select->field;
		if (arg_needs_temp(f_inner, pos, jvalue, top_level_tag, level))
			return true;

		if ((tmp = json_value_get_object(jvalue))) {
			if (!(sel = json_object_get_value(tmp, f_inner->name)))
				die("   no selector for '%s'", f_inner->name);
		} else {
			sel = jvalue;
		}

		v = parse_field(NULL, NULL, &unused, pos, f_inner, sel,
				true, false);

		f = select_field(NULL, pos, f->desc.d_select, v);
		if (f)
			return arg_needs_temp(f, pos, jvalue, NULL, level + 1);

		return false;
	case FDPATH:
	case STRING:
		return false;
	case STRUCT:
		for (f_inner = f->desc.d_struct; f_inner->name; f_inner++) {
			JSON_Value *f_value;

			tmp = json_value_get_object(jvalue);
			f_value = json_object_get_value(tmp, f_inner->name);
			if (!f_value)
				continue;

			if (arg_needs_temp(f, pos, f_value, NULL, level + 1))
				return true;
		}

		return false;
	default:
		;
	}

	return false;
}

static struct gluten_offset parse_arg(struct gluten_ctx *g, struct arg *args,
				      struct arg *a, bool multi_field,
				      struct gluten_offset offset,
				      JSON_Value *jvalue)
{
	bool top_level_tag = false;

	debug("   Parsing call argument %s", a->f.name);

	if (offset.type != OFFSET_NULL) {
		parse_field(g, args, &offset, a->pos, &a->f, jvalue,
			    false, true);
		return offset;
	}

	if (arg_needs_temp(&a->f, a->pos, jvalue, &top_level_tag, 0) ||
	    multi_field || (a->f.flags & RBUF)) {
		if (a->f.size)
			offset = gluten_rw_alloc(g, a->f.size);
		else
			offset = gluten_rw_alloc_type(g, a->f.type);
	} else if ((a->f.size && !top_level_tag)) {
		offset = gluten_ro_alloc(g, a->f.size);
	}
	parse_field(g, args, &offset, a->pos, &a->f, jvalue, false, false);

	return offset;
}

static void parse_call(struct gluten_ctx *g, struct context_desc *cdesc,
		       long nr, JSON_Object *obj, const char *ret,
		       struct arg *args)
{
	struct gluten_offset offset[6] = { 0 }, ret_offset = { 0 };
	bool is_ptr[6] = { false };
	/* Minimum requirements for argument specification:
	 * - if argument can be FDPATH, exactly one value for that position
	 * - if argument is a size field, value is optional
	 * - otherwise, every argument needs to be specified
	 */
	struct {
		bool needs_fd;
		bool has_fd;
		bool found;
		bool multi_field;
	} arg_check[6] = { 0 };
	int arg_max_pos = -1;
	unsigned count = 0;
	struct arg *a;

	/* Set requirements first */
	for (a = args; a->f.name; a++) {
		if (a->f.type == SELECTED) {
			if (!g->selected_arg[a->pos])
				die("  No argument selected for %s", a->f.name);
			a = g->selected_arg[a->pos];
		}

		if (arg_check[a->pos].found)
			arg_check[a->pos].multi_field = true;
		arg_check[a->pos].found = true;

		if (a->f.type == FDPATH)
			arg_check[a->pos].needs_fd = true;

		if (a->f.size)
			is_ptr[a->pos] = true;

		if (a->pos > arg_max_pos)
			arg_max_pos = a->pos;
	}

	/* TODO: Factor this out into a function in... parse.c? */
	for (a = args; a->f.name; a++) {
		JSON_Value *jvalue;
		bool multi_field;

		if (a->f.type == SELECTED)
			a = g->selected_arg[a->pos];

		multi_field = arg_check[a->pos].multi_field;

		/* Not common with parse_match(), though */
		if ((jvalue = json_object_get_value(obj, a->f.name))) {
			if (arg_check[a->pos].has_fd)
				die("  Conflicting value for %s", a->f.name);
			else if (arg_check[a->pos].needs_fd)
				arg_check[a->pos].has_fd = true;

			offset[a->pos] = parse_arg(g, args, a, multi_field,
						   offset[a->pos], jvalue);
			count++;
		} else if (arg_check[a->pos].needs_fd &&
			   arg_check[a->pos].has_fd) {
			;
		} else if (a->f.flags & SIZE) {
			offset[a->pos] = parse_arg(g, args, a, multi_field,
						   offset[a->pos], jvalue);
		} else {
			die("  No specification for argument %s", a->f.name);
		}
	}

	if (ret) {
		ret_offset = gluten_rw_alloc_type(g, U64);
		gluten_add_tag_post(g, ret, ret_offset);
	}

	if (count != json_object_get_count(obj))
		die("  Stray elements in call");

	emit_call(g, cdesc, nr, arg_max_pos + 1, is_ptr, offset, ret_offset);
}

static void parse_context(struct context_desc *cdesc, JSON_Object *obj)
{
	unsigned i, n = 0;

	/* Key order gives setns() order */
	for (i = 0; i < json_object_get_count(obj); i++) {
		const char *name = json_object_get_name(obj, i);
		const char **ctx_name, *str;
		enum context_type type;
		double num;

		for (ctx_name = context_type_name; *ctx_name; ctx_name++) {
			if (!strcmp(name, *ctx_name))
				break;
		}

		if (!*ctx_name)
			die("invalid context type \"%s\"", name);

		type = ctx_name - context_type_name;
		cdesc[n].type = type;
		if ((str = json_object_get_string(obj, name))) {
			if (!strcmp(str, "init"))
				continue;

			debug("   '%s' context: %s", name, str);

			if (!strcmp(str, "caller")) {
				cdesc[n].spec = CONTEXT_SPEC_CALLER;
			} else {
				cdesc[n].spec = CONTEXT_SPEC_NAME;
				if (type == UID || type == GID) {
					strncpy(cdesc[n].target.name, str,
						LOGIN_NAME_MAX);
				} else {
					strncpy(cdesc[n].target.path, str,
						PATH_MAX);
				}
			}
		} else if ((num = json_object_get_number(obj, name))) {
			debug("   '%s' context: %lli", name, num);

			cdesc[n].spec = CONTEXT_SPEC_NUM;
			if (type == UID)
				cdesc[n].target.uid = num;
			else if (type == GID)
				cdesc[n].target.gid = num;
			else
				cdesc[n].target.pid = num;
		} else {
			die("invalid context specification");
		}
		n++;
	}
}

void handle_calls(struct gluten_ctx *g, JSON_Value *value)
{
	JSON_Array *calls = json_value_get_array(value);
	unsigned i, j, count;
	int n;

	if (calls)
		count = json_array_get_count(calls);
	else
		count = 1;

	for (i = 0; i < count; i++) {
		struct context_desc cdesc[CONTEXT_TYPE_MAX + 1] = { 0 };
		JSON_Object *obj, *args, *ctx;
		struct call **set, *call;
		const char *name, *ret;

		if (calls)
			obj = json_array_get_object(calls, i);
		else
			obj = json_value_get_object(value);

		for (j = 0, n = -1; j < json_object_get_count(obj); j++) {
			if (strcmp(json_object_get_name(obj, j), "ret") &&
			    strcmp(json_object_get_name(obj, j), "context")) {
				if (n >= 0)
					die("stray object in \"call\"");
				n = j;
			}
		}

		name = json_object_get_name(obj, n);
		value = json_object_get_value_at(obj, n);
		args = json_object_get_object(obj, name);

		debug(" Parsing call %s", name);

		ret = json_object_get_string(obj, "ret");

		ctx = json_object_get_object(obj, "context");
		parse_context(cdesc, ctx);

		/* TODO: Factor this out into a function in calls.c */
		for (set = call_sets, call = set[0]; *set; ) {
			if (!call->name) {
				set++;
				call = set[0];
				continue;
			}

			if (!strcmp(name, call->name)) {
				debug("  Found description for %s",
				      name);
				parse_call(g, cdesc, call->number,
					   args, ret, call->args);
				break;
			}
			call++;
		}
	}
}

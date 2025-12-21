/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <stdarg.h>
#include <string.h>

#include <vppinfra/args.h>
#include <vppinfra/error.h>
#include <vppinfra/format_table.h>
#include <vppinfra/mem.h>

static clib_args_t *
clib_args_alloc (void)
{
  clib_args_t *h;

  h = clib_mem_alloc (sizeof (*h));
  clib_memset (h, 0, sizeof (*h));
  return h;
}

static int
clib_args_find_arg_by_name (clib_args_handle_t h, char *fmt, va_list *va)
{
  clib_arg_t *a;
  u8 *name = 0;

  if (h == 0 || h->args == 0 || fmt == 0)
    return -1;

  name = va_format (0, fmt, va);
  vec_add1 (name, 0);
  vec_foreach (a, h->args)
    if (a->name && strcmp (a->name, (char *) name) == 0)
      {
	int idx = a - h->args;
	vec_free (name);
	return idx;
      }

  vec_free (name);
  return -1;
}

static void
clib_arg_copy_enum_vals_from_array (clib_arg_t *copy, clib_arg_enum_val_t *src)
{
  for (clib_arg_enum_val_t *ev = src; ev->name; ev++)
    {
      clib_arg_enum_val_t *v;
      vec_add2 (copy->enum_vals, v, 1);
      v->val = ev->val;
      v->name = ev->name ? (char *) format (0, "%s%c", ev->name, 0) : 0;
    }
}

static void
clib_arg_copy_enum_vals_from_vec (clib_arg_t *copy, clib_arg_enum_val_t *src)
{
  clib_arg_enum_val_t *ev;
  vec_foreach (ev, src)
    {
      clib_arg_enum_val_t *v;
      vec_add2 (copy->enum_vals, v, 1);
      v->val = ev->val;
      v->name = ev->name ? (char *) format (0, "%s%c", ev->name, 0) : 0;
    }
}

static void
clib_arg_clear_value (clib_args_handle_t h, clib_arg_t *a)
{
  if (h == 0 || a == 0)
    return;

  uword idx = a - h->args;
  if (clib_bitmap_get (h->value_set_bmp, idx) == 0)
    return;

  if (a->type == CLIB_ARG_TYPE_STRING)
    vec_free (h->values[idx].string);

  h->values[idx] = (clib_arg_value_t){};
  h->value_set_bmp = clib_bitmap_set (h->value_set_bmp, idx, 0);
}

__clib_export clib_error_t *
clib_args_parse (clib_args_handle_t h, u8 *str)
{
  clib_arg_t *args = h ? h->args : 0;
  clib_error_t *err = 0;
  unformat_input_t in;
  u8 *name = 0;

  if (args == 0 || str == 0)
    return 0;

  unformat_init_string (&in, (char *) str, vec_len (str));

  while (unformat (&in, "%U=", unformat_token, "a-zA-Z0-9_", &name))
    {
      clib_arg_t *a = args;
      vec_add1 (name, 0);
      for (; a < vec_end (args) &&
	     !(a->name && strcmp (a->name, (char *) name) == 0);
	   a++)
	;

      if (a == vec_end (args))
	{
	  err = clib_error_return (0, "unknown argument '%s'", name);
	  goto done;
	}

      uword idx = a - args;
      clib_arg_value_t *val = &h->values[idx];

      if (a->type == CLIB_ARG_TYPE_BOOL)
	{

	  if (unformat (&in, "true") || unformat (&in, "1") ||
	      unformat (&in, "on") || unformat (&in, "yes"))
	    val->boolean = 1;
	  else if (unformat (&in, "false") || unformat (&in, "0") ||
		   unformat (&in, "off") || unformat (&in, "no"))
	    val->boolean = 0;
	  else
	    {
	      err = clib_error_return (
		0,
		"boolean value expected ('yes', 'no', '0', '1', 'on', "
		"'off', 'true' or 'false') for argument '%s', found '%U'",
		a->name, format_unformat_error, &in);
	      goto done;
	    }
	}
      else if (a->type == CLIB_ARG_TYPE_UINT32 ||
	       a->type == CLIB_ARG_TYPE_HEX32)
	{
	  u32 parsed_val, min = 0, max = CLIB_U32_MAX;
	  if (!unformat (&in, "0x%x", &parsed_val) &&
	      !unformat (&in, "%u", &parsed_val))
	    {
	      err = clib_error_return (
		0,
		"unsigned integer in range %u - %u expected for "
		"argument '%s', found '%U'",
		min, max, a->name, format_unformat_error, &in);
	      goto done;
	    }

	  if (a->min || a->max)
	    {
	      min = a->min;
	      max = a->max;
	    }

	  if (parsed_val < min || parsed_val > max)
	    {
	      err = clib_error_return (
		0,
		"unsigned integer in range %u - %u expected for "
		"argument '%s', found '%u'",
		min, max, a->name, parsed_val);
	      goto done;
	    }
	  val->uint32 = parsed_val;
	}
      else if (a->type == CLIB_ARG_TYPE_ENUM)
	{
	  u8 *s;
	  if (!unformat (&in, "%U", unformat_token, "a-zA-Z0-9_", &s))
	    {
	      err = clib_error_return (
		0, "enum string expected for argument '%s', found '%U'",
		a->name, format_unformat_error, &in);
	      goto done;
	    }

	  vec_add1 (s, 0);

	  if (a->enum_vals)
	    {
	      clib_arg_enum_val_t *ev;
	      vec_foreach (ev, a->enum_vals)
		if (strcmp (ev->name, (char *) s) == 0)
		  {
		    val->enum_val = ev->val;
		    vec_free (s);
		    s = 0;
		    break;
		  }
	    }

	  if (s)
	    {
	      err = clib_error_return (
		0, "unknown enum value '%s' for argument '%s'", s, a->name);
	      vec_free (s);
	      goto done;
	    }
	}
      else if (a->type == CLIB_ARG_TYPE_STRING)
	{
	  clib_arg_clear_value (h, a);
	  if (!unformat (&in, "%U", unformat_double_quoted_string,
			 &val->string))
	    {
	      err = clib_error_return (
		0,
		"double quoted string expected for argument '%s', found '%U'",
		a->name, format_unformat_error, &in);
	      goto done;
	    }

	  if (a->min && vec_len (val->string) < a->min)
	    {
	      err = clib_error_return (
		0, "string '%v' too short, must be at least %u chars",
		val->string, a->min);
	      goto done;
	    }
	  if (a->max && vec_len (val->string) > a->max)
	    {
	      err = clib_error_return (
		0, "string '%v' too long, must be no longer than %u chars",
		val->string, a->max);
	      goto done;
	    }
	}
      else
	{
	  err = clib_error_return (0, "unknown argument '%s'", name);
	  goto done;
	}

      h->value_set_bmp = clib_bitmap_set (h->value_set_bmp, idx, 1);
      vec_free (name);
      name = 0;
      unformat (&in, ",");
    }

  if (unformat_check_input (&in) != UNFORMAT_END_OF_INPUT)
    err = clib_error_return (0, "unable to parse argument name '%U'",
			     format_unformat_error, &in);

done:
  if (err)
    {
      clib_arg_t *a = 0;
      vec_foreach (a, args)
	clib_arg_clear_value (h, a);
    }

  vec_free (name);
  unformat_free (&in);
  return err;
}

__clib_export u8 *
format_clib_arg_type (u8 *s, va_list *args)
{
  clib_arg_type_t t = va_arg (*args, u32);
  switch (t)
    {
#define _(n)                                                                  \
  case CLIB_ARG_TYPE_##n:                                                     \
    return format (s, #n);
      foreach_clib_arg_type
#undef _
	default : ASSERT (0);
      break;
    }
  return s;
}

__clib_export u8 *
format_clib_arg_value (u8 *s, va_list *args)
{
  clib_arg_t *a = va_arg (*args, clib_arg_t *);
  clib_arg_value_t *v = va_arg (*args, clib_arg_value_t *);

  if (a->type == CLIB_ARG_TYPE_ENUM)
    {
      if (a->enum_vals)
	{
	  clib_arg_enum_val_t *ev;
	  vec_foreach (ev, a->enum_vals)
	    if (ev->val == v->enum_val)
	      return format (s, "%s", ev->name);
	}
      return format (s, "%d", v->enum_val);
    }

  if (a->type == CLIB_ARG_TYPE_UINT32)
    return format (s, "%u", v->uint32);

  if (a->type == CLIB_ARG_TYPE_HEX32)
    return format (s, "0x%08x", v->uint32);

  if (a->type == CLIB_ARG_TYPE_BOOL)
    return format (s, "%s", v->boolean ? "true" : "false");

  if (a->type == CLIB_ARG_TYPE_STRING)
    return format (s, "'%v'", v->string);

  ASSERT (0);

  return s;
}

__clib_export u8 *
format_clib_args (u8 *s, va_list *va)
{
  clib_args_handle_t h = va_arg (*va, clib_args_handle_t);
  clib_arg_t *a, *args = h ? h->args : 0;
  table_t t = { .no_ansi = 1 };

  table_add_header_col (&t, 4, "Name", "Value", "Default", "Description");
  table_set_cell_align (&t, -1, 0, TTAA_LEFT);
  table_set_cell_align (&t, -1, 3, TTAA_LEFT);
  vec_foreach (a, args)
    {
      int r = a - args;
      table_format_cell (&t, r, 0, "%s", a->name);
      if (clib_bitmap_get (h->value_set_bmp, r))
	table_format_cell (&t, r, 1, "%U", format_clib_arg_value, a,
			   &h->values[r]);
      else
	table_format_cell (&t, r, 1, "<not set>");

      table_format_cell (&t, r, 2, "%U", format_clib_arg_value, a,
			 &a->default_val);
      table_format_cell (&t, r, 3, "%s", a->desc);
      table_set_cell_align (&t, r, 0, TTAA_LEFT);
      table_set_cell_align (&t, r, 3, TTAA_LEFT);
    }

  s = format (s, "%U", format_table, &t);

  table_free (&t);
  return s;
}

__clib_export int
clib_args_get_enum_val_by_name (clib_args_handle_t h, char *fmt, ...)
{
  clib_arg_t *a;
  va_list va;
  int rv = 0;
  int idx;

  if (h == 0 || h->args == 0 || fmt == 0)
    return 0;

  va_start (va, fmt);
  idx = clib_args_find_arg_by_name (h, fmt, &va);
  va_end (va);

  if (idx >= 0)
    {
      a = h->args + idx;
      ASSERT (a->type == CLIB_ARG_TYPE_ENUM);
      rv = clib_bitmap_get (h->value_set_bmp, idx) ? h->values[idx].enum_val :
						     a->default_val.enum_val;
      return rv;
    }

  ASSERT (0);
  return rv;
}

__clib_export u32
clib_args_get_uint32_val_by_name (clib_args_handle_t h, char *fmt, ...)
{
  clib_arg_t *a;
  va_list va;
  u32 rv = 0;
  int idx;

  if (h == 0 || h->args == 0 || fmt == 0)
    return 0;

  va_start (va, fmt);
  idx = clib_args_find_arg_by_name (h, fmt, &va);
  va_end (va);

  if (idx >= 0)
    {
      a = h->args + idx;
      ASSERT (a->type == CLIB_ARG_TYPE_UINT32 ||
	      a->type == CLIB_ARG_TYPE_HEX32);
      rv = clib_bitmap_get (h->value_set_bmp, idx) ? h->values[idx].uint32 :
						     a->default_val.uint32;
      return rv;
    }

  ASSERT (0);
  return rv;
}

__clib_export int
clib_args_get_bool_val_by_name (clib_args_handle_t h, char *fmt, ...)
{
  clib_arg_t *a;
  va_list va;
  int rv = 0;
  int idx;

  if (h == 0 || h->args == 0 || fmt == 0)
    return 0;

  va_start (va, fmt);
  idx = clib_args_find_arg_by_name (h, fmt, &va);
  va_end (va);

  if (idx >= 0)
    {
      a = h->args + idx;
      ASSERT (a->type == CLIB_ARG_TYPE_BOOL);
      rv = clib_bitmap_get (h->value_set_bmp, idx) ? h->values[idx].boolean :
						     a->default_val.boolean;
      return rv;
    }

  ASSERT (0);
  return rv;
}

__clib_export clib_args_handle_t
clib_args_init (clib_arg_t *args)
{
  clib_args_t *h;

  if (args == 0)
    return 0;

  h = clib_args_alloc ();

  for (clib_arg_t *a = args; a->type != CLIB_ARG_END; a++)
    {
      clib_arg_t copy = *a;

      copy.name = a->name ? (char *) format (0, "%s%c", a->name, 0) : 0;
      copy.desc = a->desc ? (char *) format (0, "%s%c", a->desc, 0) : 0;
      copy.enum_vals = 0;
      if (a->enum_vals)
	clib_arg_copy_enum_vals_from_array (&copy, a->enum_vals);
      if (a->type == CLIB_ARG_TYPE_STRING)
	{
	  copy.default_val.string =
	    a->default_val.string ? vec_dup (a->default_val.string) : 0;
	}

      vec_add1 (h->args, copy);
      vec_add1 (h->values, (clib_arg_value_t){});
    }

  return h;
}

__clib_export clib_args_handle_t
clib_args_clone (clib_args_handle_t src)
{
  clib_args_t *h;
  clib_arg_t *a;

  if (src == 0 || src->args == 0)
    return 0;

  h = clib_args_alloc ();

  vec_foreach (a, src->args)
    {
      clib_arg_t copy = *a;

      copy.name = a->name ? (char *) format (0, "%s%c", a->name, 0) : 0;
      copy.desc = a->desc ? (char *) format (0, "%s%c", a->desc, 0) : 0;
      copy.enum_vals = 0;
      if (a->enum_vals)
	clib_arg_copy_enum_vals_from_vec (&copy, a->enum_vals);
      if (a->type == CLIB_ARG_TYPE_STRING)
	copy.default_val.string =
	  a->default_val.string ? vec_dup (a->default_val.string) : 0;

      vec_add1 (h->args, copy);
      vec_add1 (h->values, (clib_arg_value_t){});
    }

  if (src->value_set_bmp)
    {
      uword n = vec_len (src->args);
      for (uword i = 0; i < n; i++)
	{
	  if (!clib_bitmap_get (src->value_set_bmp, i))
	    continue;
	  h->value_set_bmp = clib_bitmap_set (h->value_set_bmp, i, 1);
	  h->values[i] = src->values[i];
	  if (h->args[i].type == CLIB_ARG_TYPE_STRING && src->values[i].string)
	    h->values[i].string = vec_dup (src->values[i].string);
	}
    }

  return h;
}

__clib_export void
clib_args_free (clib_args_handle_t h)
{
  clib_arg_t *a;
  if (h == 0)
    return;

  vec_foreach (a, h->args)
    {
      uword idx = a - h->args;
      clib_arg_enum_val_t *ev;
      if (a->type == CLIB_ARG_TYPE_STRING)
	{
	  if (clib_bitmap_get (h->value_set_bmp, idx))
	    vec_free (h->values[idx].string);
	  vec_free (a->default_val.string);
	}

      vec_foreach (ev, a->enum_vals)
	vec_free (ev->name);
      vec_free (a->enum_vals);

      vec_free (a->name);
      vec_free (a->desc);
    }

  vec_free (h->args);
  vec_free (h->values);
  vec_free (h->value_set_bmp);
  clib_mem_free (h);
}

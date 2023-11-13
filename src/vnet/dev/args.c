/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/pool.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/log.h>
#include <vnet/dev/types.h>
#include <vppinfra/format_table.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "args",
};

void
vnet_dev_arg_clear_value (vnet_dev_arg_t *a)
{
  if (a->type == VNET_DEV_ARG_TYPE_STRING)
    vec_free (a->val.string);
  a->val = (typeof (a->val)){};
  a->val_set = 0;
}

void
vnet_dev_arg_free (vnet_dev_arg_t **vp)
{
  vnet_dev_arg_t *v;
  vec_foreach (v, *vp)
    vnet_dev_arg_clear_value (v);
  vec_free (*vp);
}

vnet_dev_rv_t
vnet_dev_arg_parse (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_arg_t *args,
		    u8 *str)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  unformat_input_t in;
  u8 *name = 0;
  u8 *err = 0;

  log_debug (dev, "input '%v'", str);
  if (args == 0)
    return rv;

  unformat_init_string (&in, (char *) str, vec_len (str));

  while (unformat (&in, "%U=", unformat_token, "a-zA-Z0-9_", &name))
    {
      vnet_dev_arg_t *a = args;
      vec_add1 (name, 0);
      while (a < vec_end (args))
	if (strcmp (a->name, (char *) name) == 0)
	  break;
	else
	  a++;

      if (a->type == VNET_DEV_ARG_TYPE_BOOL)
	{

	  if (unformat (&in, "true") || unformat (&in, "1") ||
	      unformat (&in, "on") || unformat (&in, "yes"))
	    a->val.boolean = 1;
	  else if (unformat (&in, "false") || unformat (&in, "0") ||
		   unformat (&in, "off") || unformat (&in, "no"))
	    a->val.boolean = 0;
	  else
	    {
	      log_err (dev, "unable to parse args: %U", format_unformat_error,
		       &in);
	      err = format (
		0,
		"boolean value expected ('yes', 'no', '0', '1', 'on', "
		"'off', 'true' or 'false') for argument '%s', found '%U'",
		a->name, format_unformat_error, &in);
	      goto done;
	    }
	}
      else if (a->type == VNET_DEV_ARG_TYPE_UINT32)
	{
	  u32 val, min = 0, max = CLIB_U32_MAX;
	  if (!unformat (&in, "%u", &val))
	    {
	      err = format (0,
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

	  if (val < min || val > max)
	    {
	      err = format (0,
			    "unsigned integer in range %u - %u expected for "
			    "argument '%s', found '%u'",
			    min, max, a->name, val);
	      goto done;
	    }
	  a->val.uint32 = val;
	}
      else if (a->type == VNET_DEV_ARG_TYPE_STRING)
	{
	  if (!unformat (&in, "%U", unformat_double_quoted_string,
			 &a->val.string))
	    {
	      err = format (
		0,
		"double quoted string expected for argument '%s', found '%U'",
		a->name, format_unformat_error, &in);
	      goto done;
	    }

	  if (a->min && vec_len (a->val.string) < a->min)
	    {
	      err =
		format (0, "string '%v' too short, must be at least %u chars",
			a->val.string, a->min);
	      goto done;
	    }
	  if (a->max && vec_len (a->val.string) > a->max)
	    {
	      err = format (
		0, "string '%v' too long, must be no longer than %u chars",
		a->val.string, a->max);
	      goto done;
	    }
	}
      else
	{
	  err = format (0, "unknown argument '%s'", name);
	  goto done;
	}

      a->val_set = 1;
      log_debug (dev, "name '%s' type %U value %U", name,
		 format_vnet_dev_arg_type, a->type, format_vnet_dev_arg_value,
		 a->type, &a->val);
      vec_free (name);
      unformat (&in, ",");
    }

  if (unformat_check_input (&in) != UNFORMAT_END_OF_INPUT)
    err = format (0, "unable to parse argument name '%U'",
		  format_unformat_error, &in);

done:
  if (err)
    {
      vnet_dev_arg_t *a = 0;
      log_err (dev, "%v", err);
      vec_free (err);
      vec_foreach (a, args)
	vnet_dev_arg_clear_value (a);
      rv = VNET_DEV_ERR_INVALID_ARG;
    }

  vec_free (name);
  unformat_free (&in);
  return rv;
}

u8 *
format_vnet_dev_arg_type (u8 *s, va_list *args)
{
  vnet_dev_arg_type_t t = va_arg (*args, u32);
  switch (t)
    {
#define _(n, f, val)                                                          \
  case VNET_DEV_ARG_TYPE_##n:                                                 \
    return format (s, #n);
      foreach_vnet_dev_arg_type
#undef _
	default : ASSERT (0);
      break;
    }
  return s;
}

u8 *
format_vnet_dev_arg_value (u8 *s, va_list *args)
{
  vnet_dev_arg_type_t t = va_arg (*args, u32);
  vnet_dev_arg_value_t *v = va_arg (*args, vnet_dev_arg_value_t *);

  switch (t)
    {
#define _(n, f, value)                                                        \
  case VNET_DEV_ARG_TYPE_##n:                                                 \
    s = format (s, f, v->value);                                              \
    break;
      foreach_vnet_dev_arg_type
#undef _
	default : break;
    }
  return s;
}

u8 *
format_vnet_dev_args (u8 *s, va_list *va)
{
  vnet_dev_arg_t *a, *args = va_arg (*va, vnet_dev_arg_t *);
  table_t t = { .no_ansi = 1 };

  table_add_header_col (&t, 4, "Name", "Value", "Default", "Description");
  table_set_cell_align (&t, -1, 0, TTAA_LEFT);
  table_set_cell_align (&t, -1, 3, TTAA_LEFT);
  vec_foreach (a, args)
    {
      int r = a - args;
      table_format_cell (&t, r, 0, "%s", a->name);
      if (a->val_set)
	table_format_cell (&t, r, 1, "%U", format_vnet_dev_arg_value, a->type,
			   &a->val);
      else
	table_format_cell (&t, r, 1, "<not set>");

      table_format_cell (&t, r, 2, "%U", format_vnet_dev_arg_value, a->type,
			 &a->default_val);
      table_format_cell (&t, r, 3, "%s", a->desc);
      table_set_cell_align (&t, r, 0, TTAA_LEFT);
      table_set_cell_align (&t, r, 3, TTAA_LEFT);
    }

  s = format (s, "%U", format_table, &t);

  table_free (&t);
  return s;
}

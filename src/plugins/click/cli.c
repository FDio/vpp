/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include "vppinfra/vec.h"
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <click/click.h>

static clib_error_t *
click_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  click_instance_create_args_t args = {};

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &args.name))
	;
      else if (unformat (input, "conf %s", &args.router_file))
	;
      else
	{
	  err = clib_error_return (0, "unknown input`%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (args.name == 0)
    {
      err = clib_error_return (0, "name required");
      goto done;
    }

  if (args.router_file == 0)
    {
      err = clib_error_return (0, "conf required");
      goto done;
    }

  err = click_instance_create (vm, &args);

done:
  vec_free (args.router_file);
  vec_free (args.name);
  return err;
}

VLIB_CLI_COMMAND (click_create_command, static) = {
  .path = "click create",
  .short_help = "click create name <name> conf <conf>",
  .function = click_create_command_fn,
  .is_mp_safe = 1,
};

__clib_export uword
unformat_click_inst_index (unformat_input_t *input, va_list *args)
{
  u32 *d = va_arg (*args, u32 *);
  click_main_t *cm = &click_main;
  click_instance_t *ci;
  u8 *name;
  uword rv = 0;

  if (!unformat (input, "%v", &name))
    return 0;

  vec_foreach (ci, cm->instances)
    {
      if (vec_cmp (ci->name, name))
	{
	  rv = 1;
	  *d = ci - cm->instances;
	  goto done;
	}
    }

done:
  vec_free (name);
  return rv;
}

static clib_error_t *
show_click_elt_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  click_main_t *cm = &click_main;
  u32 inst_index = CLIB_U32_MAX;
  clib_error_t *err = 0;
  click_instance_t *ci;
  vppclick_elt_info_t ei;
  int elt_index = 0;
  u8 *s = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "instance %U", unformat_click_inst_index,
		    &inst_index))
	;
      else
	{
	  err = clib_error_return (0, "unknown input`%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (inst_index == CLIB_U32_MAX)
    {
      if (pool_elts (cm->instances) == 1)
	{
	  inst_index = pool_get_first_index (cm->instances);
	}
      else
	{
	  err = clib_error_return (
	    0, "Multiple instances present. Please specify instance name.");
	  goto done;
	}
    }

  ci = pool_elt_at_index (cm->instances, inst_index);

  while (vppclick_get_elt_info (ci->ctx, elt_index, &ei) == 0)
    {
      vlib_cli_output (vm, "name: '%s' class: '%s', eindex: %d", ei.name,
		       ei.class_name, elt_index);
      vlib_cli_output (vm, "  config: '%s'", ei.config);
      vlib_cli_output (vm, "  home thread id: %d", ei.home_thread_id);
      if (ei.n_inputs)
	{
	  vlib_cli_output (vm, "  inputs:");
	  for (int i = 0; i < ei.n_inputs; i++)
	    {
	      vppclick_elt_port_info_t pi;
	      vppclick_elt_info_t pei;

	      vppclick_get_elt_port_info (ci->ctx, elt_index, i, false, &pi);
	      vppclick_get_elt_info (ci->ctx, pi.eindex, &pei);

	      vec_reset_length (s);
	      s = format (s, "[%u] %s (%s)", i, pei.name, pei.class_name);

	      if (pi.is_pull)
		s = format (s, ", pull");
	      if (pi.is_push)
		s = format (s, ", push");

	      vlib_cli_output (vm, "    %v", s);
	    }
	}
      if (ei.n_outputs)
	{
	  vlib_cli_output (vm, "  outputs:");
	  for (int i = 0; i < ei.n_outputs; i++)
	    {
	      vppclick_elt_port_info_t pi;
	      vppclick_elt_info_t pei;

	      vppclick_get_elt_port_info (ci->ctx, elt_index, i, true, &pi);
	      vppclick_get_elt_info (ci->ctx, pi.eindex, &pei);

	      vec_reset_length (s);
	      s = format (s, "[%u] %s (%s)", i, pei.name, pei.class_name);

	      if (pi.is_pull)
		s = format (s, ", pull");
	      if (pi.is_push)
		s = format (s, ", push");

	      vlib_cli_output (vm, "    %v", s);
	    }
	}
      if (ei.n_handlers)
	{
	  const char *flag_str;

	  vlib_cli_output (vm, "  handlers:");
	  for (int i = 0; i < ei.n_handlers; i++)
	    {
	      u32 flags;
	      vppclick_handler_info_t hi;
	      vppclick_get_handler_info (ci->ctx, ei.handler_indices[i], &hi);
	      vec_reset_length (s);
	      s =
		format (s, "[%3d] '%s', flags:", hi.hindex, hi.name, hi.flags);

	      flags = hi.flags;
	      do
		{
		  flag_str = vppclick_get_one_handler_flag_str (&flags);
		  if (flag_str)
		    s = format (s, " %s", flag_str);
		}
	      while (flags && flag_str);
	      if (flags)
		s = format (s, ", unknown flags (0x%x)", flags);
	      vlib_cli_output (vm, "    %v", s);
	    }
	}
      vlib_cli_output (vm, "\n");
      elt_index++;
    }

done:
  vec_free (s);
  return err;
}

VLIB_CLI_COMMAND (show_click_elt_cmd, static) = {
  .path = "show click element",
  .short_help = "show clicke element",
  .function = show_click_elt_cmd_fn,
  .is_mp_safe = 1,
};

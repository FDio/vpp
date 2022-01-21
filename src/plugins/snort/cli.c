/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <snort/snort.h>

static u8 *
format_snort_instance (u8 *s, va_list *args)
{
  snort_instance_t *i = va_arg (*args, snort_instance_t *);
  s = format (s, "%s [idx:%d sz:%d fd:%d]", i->name, i->index, i->shm_size,
	      i->shm_fd);

  return s;
}

static clib_error_t *
snort_create_instance_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *err = 0;
  u8 *name = 0;
  u32 queue_size = 1024;
  u8 drop_on_diconnect = 1;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "queue-size %u", &queue_size))
	;
      else if (unformat (line_input, "on-disconnect drop"))
	drop_on_diconnect = 1;
      else if (unformat (line_input, "on-disconnect pass"))
	drop_on_diconnect = 0;
      else if (unformat (line_input, "name %s", &name))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (!is_pow2 (queue_size))
    {
      err = clib_error_return (0, "Queue size must be a power of two");
      goto done;
    }

  if (!name)
    {
      err = clib_error_return (0, "please specify instance name");
      goto done;
    }

  err = snort_instance_create (vm, (char *) name, min_log2 (queue_size),
			       drop_on_diconnect);

done:
  vec_free (name);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (snort_create_instance_command, static) = {
  .path = "snort create-instance",
  .short_help = "snort create-instaince name <name> [queue-size <size>] "
		"[on-disconnect drop|pass]",
  .function = snort_create_instance_command_fn,
};

static clib_error_t *
snort_attach_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *err = 0;
  u8 *name = 0;
  u32 sw_if_index = ~0;
  snort_attach_dir_t dir = SNORT_INOUT;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (line_input, "instance %s", &name))
	;
      else if (unformat (line_input, "input"))
	dir = SNORT_INPUT;
      else if (unformat (line_input, "output"))
	dir = SNORT_OUTPUT;
      else if (unformat (line_input, "inout"))
	dir = SNORT_INOUT;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      err = clib_error_return (0, "please specify interface");
      goto done;
    }

  if (!name)
    {
      err = clib_error_return (0, "please specify instance name");
      goto done;
    }

  err =
    snort_interface_enable_disable (vm, (char *) name, sw_if_index, 1, dir);

done:
  vec_free (name);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (snort_attach_command, static) = {
  .path = "snort attach",
  .short_help = "snort attach instance <name> interface <if-name> "
		"[input|ouput|inout]",
  .function = snort_attach_command_fn,
};

static clib_error_t *
snort_detach_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *err = 0;
  u32 sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      err = clib_error_return (0, "please specify interface");
      goto done;
    }

  err = snort_interface_enable_disable (vm, 0, sw_if_index, 0, SNORT_INOUT);

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (snort_detach_command, static) = {
  .path = "snort detach",
  .short_help = "snort detach interface <if-name>",
  .function = snort_detach_command_fn,
};

static clib_error_t *
snort_show_instances_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;

  pool_foreach (si, sm->instances)
    vlib_cli_output (vm, "%U", format_snort_instance, si);

  return 0;
}

VLIB_CLI_COMMAND (snort_show_instances_command, static) = {
  .path = "show snort instances",
  .short_help = "show snort instances",
  .function = snort_show_instances_command_fn,
};

static clib_error_t *
snort_show_interfaces_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  snort_main_t *sm = &snort_main;
  vnet_main_t *vnm = vnet_get_main ();
  snort_instance_t *si;
  u32 *index;

  vlib_cli_output (vm, "interface\tsnort instance");
  vec_foreach (index, sm->instance_by_sw_if_index)
    {
      if (index[0] != ~0)
	{
	  si = vec_elt_at_index (sm->instances, index[0]);
	  vlib_cli_output (vm, "%U:\t%s", format_vnet_sw_if_index_name, vnm,
			   index - sm->instance_by_sw_if_index, si->name);
	}
    }
  return 0;
}

VLIB_CLI_COMMAND (snort_show_interfaces_command, static) = {
  .path = "show snort interfaces",
  .short_help = "show snort interfaces",
  .function = snort_show_interfaces_command_fn,
};

static clib_error_t *
snort_show_clients_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  snort_main_t *sm = &snort_main;
  vlib_cli_output (vm, "number of clients: %d", pool_elts (sm->clients));
  return 0;
}

VLIB_CLI_COMMAND (snort_show_clients_command, static) = {
  .path = "show snort clients",
  .short_help = "show snort clients",
  .function = snort_show_clients_command_fn,
};

static clib_error_t *
snort_mode_polling_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  return snort_set_node_mode (vm, VLIB_NODE_STATE_POLLING);
}

static clib_error_t *
snort_mode_interrupt_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  return snort_set_node_mode (vm, VLIB_NODE_STATE_INTERRUPT);
}

VLIB_CLI_COMMAND (snort_mode_polling_command, static) = {
  .path = "snort mode polling",
  .short_help = "snort mode polling|interrupt",
  .function = snort_mode_polling_command_fn,
};

VLIB_CLI_COMMAND (snort_mode_interrupt_command, static) = {
  .path = "snort mode interrupt",
  .short_help = "snort mode polling|interrupt",
  .function = snort_mode_interrupt_command_fn,
};

static clib_error_t *
snort_show_mode_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  snort_main_t *sm = &snort_main;
  char *mode =
    sm->input_mode == VLIB_NODE_STATE_POLLING ? "polling" : "interrupt";
  vlib_cli_output (vm, "input mode: %s", mode);
  return 0;
}

VLIB_CLI_COMMAND (snort_show_mode_command, static) = {
  .path = "show snort mode",
  .short_help = "show snort mode",
  .function = snort_show_mode_command_fn,
};

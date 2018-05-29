/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <snort/snort.h>

static clib_error_t *
snort_command_fn (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  snort_enable_disable_args_t args;
  clib_error_t *error = 0;
  u32 is_enable = 1;
  u8 sif_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &args.sw_if_index))
	sif_set = 1;
      else if (unformat (line_input, "disable"))
	is_enable = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
		                     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (is_enable && !sif_set)
    {
      error = clib_error_return (0, "sw_if_index not set");
      goto done;
    }
  args.is_en = is_enable;
  if (snort_enable_disable (&args))
    error = clib_error_return (0, "failed to enable");

  done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
snort_feature_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snort_interface_add_del_args_t _args, *args = &_args;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0, is_add = 1;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
		                     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == (u32) ~0)
    {
      error = clib_error_return (0, "unknown interface provided");
      goto done;
    }

  args->is_add = is_add;
  args->sw_if_index = sw_if_index;
  if (snort_interface_add_del (args))
    error = clib_error_return (0, "failed to %s snort on interface %u",
	                       is_add ? "enable" : "disable", sw_if_index);

done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
snort_feature_status_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  snort_main_t *sm = snort_get_main ();

  vlib_cli_output (vm, "status: %s", sm->is_enabled ? "enabled" : "disabled");
  if (!sm->is_enabled)
    return 0;

  vlib_cli_output (vm, "snort interface: %U", format_vnet_sw_if_index_name,
	           vnet_get_main (), sm->sw_if_index);
  return 0;
}

static clib_error_t *
show_snort_interface_fn (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snort_main_t *sm = snort_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  if (!sm->is_enabled)
    {
      vlib_cli_output ("feature not enabled");
      return 0;
    }

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
	            &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return(0, "unknown input '%U'",
		                    format_unformat_error, line_input);
	  goto done;
	}
    }

}

VLIB_CLI_COMMAND (snort_interface_command, static) = {
  .path = "show snort interface",
  .function = show_snort_interface_fn,
  .short_help = "show snort interface",
};

VLIB_CLI_COMMAND (snort_feature_status_command, static) = {
  .path = "show snort status",
  .function = snort_feature_status_fn,
  .short_help = "show snort status",
};

/*?
 * @cliexpar
 * @cliexstart{set interface snort}
 * Enable/disable snort feature on the interface.
 * To enable snort feature use:
 *  vpp# set interface snort GigabitEthernetX/X/X
 * @cliexend
?*/
VLIB_CLI_COMMAND (snort_set_interface_command, static) = {
  .path = "set interface snort",
  .function = snort_feature_command_fn,
  .short_help = "set interface snort <iface> [del]",
};

/*?
 * @cliexpar
 * @cliexstart{snort enable|disable}
 * Enable/disable snort plugin.
 * To enable snort feature use:
 *  vpp# snort enable memif0/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (snort_enable_command, static) = {
  .path = "snort",
  .function = snort_command_fn,
  .short_help = "snort enable|disable [snort interface]",
};

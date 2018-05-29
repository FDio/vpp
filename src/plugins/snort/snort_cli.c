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
snort_enable_command_fn (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  if (snort_enable_disable (1/* enable */))
    return clib_error_return (0, "failed to enable");
  return 0;
}

static clib_error_t *
snort_feature_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
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

  if (snort_interface_add_del (sw_if_index, is_add))
    error = clib_error_return (0, "failed to %s snort on interface %u",
	                       is_add ? "enable" : "disable", sw_if_index);

done:
  unformat_free (line_input);
  return error;
}

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

VLIB_CLI_COMMAND (snort_enable_command, static) = {
  .path = "snort enable",
  .function = snort_enable_command_fn,
  .short_help = "set enable",
};

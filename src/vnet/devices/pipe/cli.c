/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Copyright (c) 2019, Vinci Consulting Corp.  All rights reserved.
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

#include <vnet/devices/pipe/pipe.h>

static clib_error_t *
create_pipe_interfaces (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv;
  u32 sw_if_index;
  u32 pipe_sw_if_index[2];
  u8 is_specified = 0;
  u32 user_instance = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "instance %d", &user_instance))
	is_specified = 1;
      else
	break;
    }

  rv = vnet_create_pipe_interface (is_specified, user_instance,
				   &sw_if_index, pipe_sw_if_index);

  if (rv)
    return clib_error_return (0, "vnet_create_pipe_interface failed");

  vlib_cli_output (vm, "Created interface %U.\n",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);
  return 0;
}

/*?
 * Create a pipe interface.
 *
 * @cliexpar
 *
 * @cliexcmd{pipe create-interface [instance <instance>]}
 * Example of how to create a pipe interface:
 * @cliexcmd{pipe create}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pipe_create_interface_command, static) = {
  .path = "create pipe",
  .short_help = "create pipe [instance <instance>]",
  .function = create_pipe_interfaces,
};
/* *INDENT-ON* */
static clib_error_t *
delete_pipe_interfaces (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int rv;
  u8 *ifname = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface not specified");

  /*  get the interface name now.  After the delete, it shows as DELETED */
  ifname =
    format (0, "%U", format_vnet_sw_if_index_name, vnet_get_main (),
	    sw_if_index);
  rv = vnet_delete_pipe_interface (sw_if_index);

  if (rv)
    return clib_error_return (0, "vnet_delete_pipe_interface failed");

  vlib_cli_output (vm, "Deleted interface %v.\n", ifname);
  vec_free (ifname);

  return 0;
}

/*?
 * Delete a pipe interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{delete pipe <interface>}
 * Example of how to delete a pipe interface:
 * @cliexcmd{delete pipe loop0}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pipe_delete_interface_command, static) = {
  .path = "delete pipe",
  .short_help = "delete pipe <interface>",
  .function = delete_pipe_interfaces,
};
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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

#include <vnet/vnet.h>

static clib_error_t *
test_interface_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_hw_interface_flags_t flags;
  vnet_main_t *vnm;
  u32 sw_if_index;

  flags = VNET_HW_INTERFACE_FLAG_NONE;
  sw_if_index = ~0;
  vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (input, "up"))
	flags = VNET_HW_INTERFACE_FLAG_LINK_UP;
      else if (unformat (input, "down"))
	;
      else
	break;
    }

  if (~0 != sw_if_index)
    {
      vnet_sw_interface_t *sw;

      sw = vnet_get_sw_interface (vnm, sw_if_index);

      vnet_hw_interface_set_flags (vnm, sw->hw_if_index, flags);
    }
  else
    {
      return clib_error_return (0, "unknown interface `%U'",
				format_unformat_error, input);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_interface_command, static) =
{
  .path = "test interface link-state",
  .short_help = "test interface link-state <interface> [up] [down]",
  .function = test_interface_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

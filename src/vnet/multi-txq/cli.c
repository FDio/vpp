/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/feature/feature.h>
#include <vnet/multi-txq/multi_txq.h>

static clib_error_t *
set_interface_feature_multi_txq_command_fn (vlib_main_t *vm,
					    unformat_input_t *input,
					    vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  u32 sw_if_index = ~0;
  u8 enable = 0;
  u32 number_of_txqs = 1;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else if (unformat (line_input, "enable"))
	enable = 1;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else if (unformat (line_input, "txq %u", &number_of_txqs))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "Interface not specified...");
      goto done;
    }
  int rv = vnet_sw_interface_multi_txq_enable_disable (sw_if_index,
						       number_of_txqs, enable);

  switch (rv)
    {
    case VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY:
      error = clib_error_return (
	0, "txq configured range should be between 1 and 8");
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "interface type is not hardware");
      break;
    default:;
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (set_interface_feature_multi_txq_command, static) = {
  .path = "set interface feature multi-txq",
  .short_help =
    "set interface feature multi-txq <intfc> [enable [txq <n>]| disable]",
  .function = set_interface_feature_multi_txq_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

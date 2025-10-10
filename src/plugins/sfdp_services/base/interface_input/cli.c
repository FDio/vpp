/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <sfdp_services/base/interface_input/interface_input.h>

static clib_error_t *
sfdp_interface_input_set_unset_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;

  clib_error_t *err = 0;
  u32 sw_if_index = ~0;
  u32 tenant_id = ~0;
  u8 unset = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat (line_input, "disable"))
	unset = 1;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  err = sfdp_interface_input_set_tenant (&sfdp_interface_input_main,
					 sw_if_index, tenant_id, unset);
done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sfdp_nat_external_interface_set_unset, static) = {
  .path = "set sfdp interface-input",
  .short_help =
    "set sfdp interface-input <interface> tenant <tenant-id> [disable]",
  .function = sfdp_interface_input_set_unset_fn,
};
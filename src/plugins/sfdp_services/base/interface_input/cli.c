/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
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
  u8 is_ip6 = 0;
  u8 offload = 0;
  u8 unset = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat (line_input, "ip6"))
	is_ip6 = 1;
      else if (unformat (line_input, "disable"))
	unset = 1;
      else if (unformat (line_input, "offload"))
	offload = 1;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  err = sfdp_interface_input_set_tenant (&sfdp_interface_input_main, sw_if_index, tenant_id, is_ip6,
					 offload, unset);
done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sfdp_interface_input_set_unset, static) = {
  .path = "set sfdp interface-input",
  .short_help = "set sfdp interface-input <interface> tenant <tenant-id> [ip6] [offload] [disable]",
  .function = sfdp_interface_input_set_unset_fn,
};
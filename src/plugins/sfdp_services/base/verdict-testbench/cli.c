/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <sfdp_services/base/verdict-testbench/verdict_testbench.h>

static clib_error_t *
set_verdict_testbench_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  verdict_testbench_main_t *vt = &verdict_testbench_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 tx_sw_if_index = ~0;
  u32 rx_sw_if_index = ~0;
  u8 is_disable = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tx-interface %U", unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
	;
      else if (unformat (input, "rx-interface %U", unformat_vnet_sw_interface, vnm,
			 &rx_sw_if_index))
	;
      else if (unformat (input, "disable"))
	is_disable = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (is_disable)
    return verdict_testbench_disable (vt);

  if (tx_sw_if_index == ~0)
    return clib_error_return (0, "tx-interface required");

  return verdict_testbench_enable (vt, tx_sw_if_index, rx_sw_if_index);
}

VLIB_CLI_COMMAND (set_verdict_testbench_command, static) = {
  .path = "set sfdp verdict-testbench",
  .short_help =
    "set sfdp verdict-testbench tx-interface <if> [rx-interface <if>] [disable]",
  .function = set_verdict_testbench_command_fn,
};

static clib_error_t *
show_verdict_testbench_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  verdict_testbench_main_t *vt = &verdict_testbench_main;

  vlib_cli_output (vm, "verdict-testbench: %s", vt->is_enabled ? "enabled" : "disabled");
  if (vt->is_enabled)
    {
      vnet_main_t *vnm = vnet_get_main ();
      vlib_cli_output (vm, "  tx-interface: %U", format_vnet_sw_if_index_name, vnm,
		       vt->tx_sw_if_index);
      if (vt->rx_sw_if_index != ~0)
	vlib_cli_output (vm, "  rx-interface: %U", format_vnet_sw_if_index_name, vnm,
			 vt->rx_sw_if_index);
      else
	vlib_cli_output (vm, "  rx-interface: all");
      vlib_cli_output (vm, "  template_index: %u", vt->verdict_template_index);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_verdict_testbench_command, static) = {
  .path = "show sfdp verdict-testbench",
  .short_help = "show sfdp verdict-testbench",
  .function = show_verdict_testbench_command_fn,
};

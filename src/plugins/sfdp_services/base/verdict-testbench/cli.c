/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <sfdp_services/base/verdict-testbench/verdict_testbench.h>

static clib_error_t *
sfdp_verdict_testbench_set_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  verdict_testbench_main_t *vt = &verdict_testbench_main;
  clib_error_t *err = 0;
  u32 sw_if_index = ~0;
  u32 host_port_id_u32 = ~0;
  u8 disable = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "host-port-id %d", &host_port_id_u32))
	;
      else if (unformat (line_input, "disable"))
	disable = 1;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnet_get_main (),
			 &sw_if_index))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (disable)
    {
      err = verdict_testbench_disable (vt);
      goto done;
    }

  if (sw_if_index == ~0)
    {
      err = clib_error_return (0, "please specify interface");
      goto done;
    }

  u16 host_port_id = (host_port_id_u32 == ~0) ? VT_HOST_PORT_ID_UNSET : (u16) host_port_id_u32;
  err = verdict_testbench_enable (vt, sw_if_index, host_port_id);

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sfdp_verdict_testbench_set, static) = {
  .path = "set sfdp verdict-testbench",
  .short_help = "set sfdp verdict-testbench <interface> [host-port-id <id>] "
		"[disable]",
  .function = sfdp_verdict_testbench_set_fn,
};

static clib_error_t *
sfdp_verdict_testbench_show_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  verdict_testbench_main_t *vt = &verdict_testbench_main;

  vlib_cli_output (vm, "verdict-testbench: %s", vt->is_enabled ? "enabled" : "disabled");

  if (vt->is_enabled)
    {
      vlib_cli_output (vm, "  interface: %U", format_vnet_sw_if_index_name, vnet_get_main (),
		       vt->sw_if_index);
      vlib_cli_output (vm, "  hw_if_index: %u", vt->hw_if_index);
      if (vt->host_port_id != VT_HOST_PORT_ID_UNSET)
	vlib_cli_output (vm, "  host-port-id: %u", vt->host_port_id);
      else
	vlib_cli_output (vm, "  host-port-id: unset");
      vlib_cli_output (vm, "  template-index: %u", vt->verdict_template_index);
      vlib_cli_output (vm, "  pkt-threshold: %u", VT_PKT_THRESHOLD);
    }

  return 0;
}

VLIB_CLI_COMMAND (sfdp_verdict_testbench_show, static) = {
  .path = "show sfdp verdict-testbench",
  .short_help = "show sfdp verdict-testbench",
  .function = sfdp_verdict_testbench_show_fn,
};

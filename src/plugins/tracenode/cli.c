/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <tracenode/tracenode.h>

static clib_error_t *
tracenode_feature_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  int enable = 1, is_pcap = 0;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	enable = 0;
      else if (unformat (line_input, "pcap"))
	is_pcap = 1;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	{
	  if (sw_if_index == 0)
	    return clib_error_return (0, "Local interface not supported...");
	}

      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Software interface required");

  if ((rv = tracenode_feature_enable_disable (sw_if_index, is_pcap, enable)) !=
      0)
    return clib_error_return (
      0, "vnet_enable_disable_tracenode_feature returned %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (tracenode_feature, static) = {
  .path = "tracenode feature",
  .short_help = "tracenode feature <intfc> [disable] [pcap]",
  .function = tracenode_feature_cmd_fn,
};

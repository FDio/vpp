/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/flow/flow.h>
#include <sfdp_services/base/verdict-testbench/verdict_testbench.h>

static clib_error_t *
set_verdict_testbench_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  verdict_testbench_main_t *vt = &verdict_testbench_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 tx_sw_if_index = ~0;
  u32 rx_sw_if_index = ~0;
  u8 enable_counters = 0;
  u8 is_disable = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tx-interface %U", unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
	;
      else if (unformat (input, "rx-interface %U", unformat_vnet_sw_interface, vnm,
			 &rx_sw_if_index))
	;
      else if (unformat (input, "enable-counters"))
	enable_counters = 1;
      else if (unformat (input, "disable"))
	is_disable = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (is_disable)
    return verdict_testbench_disable (vt);

  if (tx_sw_if_index == ~0)
    return clib_error_return (0, "tx-interface required");

  return verdict_testbench_enable (vt, tx_sw_if_index, rx_sw_if_index, enable_counters);
}

VLIB_CLI_COMMAND (set_verdict_testbench_command, static) = {
  .path = "set sfdp verdict-testbench",
  .short_help = "set sfdp verdict-testbench tx-interface <if> "
		"[rx-interface <if>] [enable-counters] [disable]",
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
      vlib_cli_output (vm, "  counters: %s", vt->enable_counters ? "enabled" : "disabled");
      vlib_cli_output (vm, "  template_index: %u", vt->verdict_template_index);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_verdict_testbench_command, static) = {
  .path = "show sfdp verdict-testbench",
  .short_help = "show sfdp verdict-testbench",
  .function = show_verdict_testbench_command_fn,
};

static clib_error_t *
show_verdict_testbench_counters_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  verdict_testbench_main_t *vt = &verdict_testbench_main;
  vnet_flow_main_t *fm = &flow_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_t *f;
  u32 n_flows = 0;

  if (!vt->is_enabled)
    return clib_error_return (0, "verdict-testbench not enabled");

  if (!vt->enable_counters)
    return clib_error_return (0, "counters not enabled (use enable-counters)");

  pool_foreach (f, fm->global_flow_pool)
    {
      if (!(f->actions & VNET_FLOW_ACTION_STEER_TO_PORT) || !(f->actions & VNET_FLOW_ACTION_COUNT))
	continue;
      if (f->driver_data.hw_if_index == ~0)
	continue;

      int rv = vnet_flow_get_counter (vnm, f->index);
      if (rv)
	continue;

      if (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE)
	{
	  vnet_flow_ip4_n_tuple_t *t = &f->pattern.ip4_n_tuple;
	  vlib_cli_output (vm, "  flow %u: %U:%u -> %U:%u proto %u  hits %lu bytes %lu", f->index,
			   format_ip4_address, &t->src_addr.addr, t->src_port.port,
			   format_ip4_address, &t->dst_addr.addr, t->dst_port.port,
			   t->protocol.prot, f->counter_hits, f->counter_bytes);
	}
      else
	{
	  vlib_cli_output (vm, "  flow %u: hits %lu bytes %lu", f->index, f->counter_hits,
			   f->counter_bytes);
	}
      n_flows++;
    }

  vlib_cli_output (vm, "total: %u flows with counters", n_flows);
  return 0;
}

VLIB_CLI_COMMAND (show_verdict_testbench_counters_command, static) = {
  .path = "show sfdp verdict-testbench counters",
  .short_help = "show sfdp verdict-testbench counters",
  .function = show_verdict_testbench_counters_fn,
};

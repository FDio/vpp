/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <unistd.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/flow/flow.h>
#include <vnet/ip/ip.h>
#include <vpp/app/version.h>

static clib_error_t *
test_flow_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_t templ;
  vnet_flow_range_t range;
  u32 hw_if_index = ~0;
  u32 template_index;
  u32 first_flow_index = ~0;
  u32 n_flows = 0;
  int rv;

  /* Timing variables */
  u64 t_template_add_0, t_template_add_1;
  u64 t_template_enable_0, t_template_enable_1;
  u64 t_flow_add_0, t_flow_add_1;
  u64 t_async_enable_0, t_async_enable_1;
  u64 t_async_disable_0, t_async_disable_1;
  u64 t_flow_del_0, t_flow_del_1;
  u64 t_template_disable_0, t_template_disable_1;
  u64 t_template_del_0, t_template_del_1;
  f64 clocks_per_second = vm->clib_time.clocks_per_second;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else if (unformat (input, "%u", &n_flows))
	;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (n_flows == 0)
    return clib_error_return (0, "please specify a number of flows to insert");

  if (hw_if_index == ~0)
    return clib_error_return (0, "please specify interface name");

  clib_memset (&templ, 0, sizeof (templ));
  templ.type = VNET_FLOW_TYPE_IP4_N_TUPLE;
  templ.actions = VNET_FLOW_ACTION_DROP;
  templ.mark_flow_id = 1;

  templ.ip4_n_tuple.src_addr.mask.as_u32 = ~0;
  templ.ip4_n_tuple.dst_addr.mask.as_u32 = ~0;
  templ.ip4_n_tuple.protocol.prot = IP_PROTOCOL_TCP;
  templ.ip4_n_tuple.protocol.mask = 0xff;
  templ.ip4_n_tuple.src_port.mask = ~0;
  templ.ip4_n_tuple.dst_port.mask = ~0;

  /* === ADD PHASE === */
  vlib_cli_output (vm, "=== Adding flows ===");

  t_template_add_0 = clib_cpu_time_now ();
  rv = vnet_flow_add_async_template (vnm, &templ, &template_index);
  t_template_add_1 = clib_cpu_time_now ();
  if (rv)
    return clib_error_return (0, "vnet_flow_add_async_template failed: %d", rv);

  vlib_cli_output (vm, "Template index: %u", template_index);

  t_template_enable_0 = clib_cpu_time_now ();
  rv = vnet_flow_async_template_enable (vnm, template_index, hw_if_index, n_flows);
  t_template_enable_1 = clib_cpu_time_now ();
  if (rv)
    return clib_error_return (0, "vnet_flow_async_template_enable failed: %d", rv);

  vlib_cli_output (vm, "Template enabled on interface");

  t_flow_add_0 = clib_cpu_time_now ();
  for (u32 i = 0; i < n_flows; i++)
    {
      u32 flow_index;
      vnet_flow_t f;
      clib_memset (&f, 0, sizeof (f));
      f.type = VNET_FLOW_TYPE_IP4_N_TUPLE;
      f.actions = VNET_FLOW_ACTION_DROP;

      /* Set specific match criteria for each flow */
      f.ip4_n_tuple.src_addr.addr.as_u32 = i;
      f.ip4_n_tuple.src_addr.mask.as_u32 = ~0;
      f.ip4_n_tuple.dst_addr.addr.as_u32 = n_flows - i;
      f.ip4_n_tuple.dst_addr.mask.as_u32 = ~0;
      f.ip4_n_tuple.protocol.prot = IP_PROTOCOL_TCP;
      f.ip4_n_tuple.protocol.mask = 0xff;
      f.ip4_n_tuple.src_port.port = i & 0xffff;
      f.ip4_n_tuple.src_port.mask = ~0;
      f.ip4_n_tuple.dst_port.port = (i >> 16) & 0xffff;
      f.ip4_n_tuple.dst_port.mask = ~0;

      rv = vnet_flow_add (vnm, &f, &flow_index);
      if (rv)
	return clib_error_return (0, "vnet_flow_add failed for flow %u: %d", i, rv);
      if (first_flow_index == ~0)
	first_flow_index = flow_index;
    }
  t_flow_add_1 = clib_cpu_time_now ();

  vlib_cli_output (vm, "Added %u flows (first index: %u)", n_flows, first_flow_index);

  range.start = first_flow_index;
  range.count = n_flows;
  range.owner = (u8 *) "flow_test";

  t_async_enable_0 = clib_cpu_time_now ();
  rv = vnet_flow_async_enable (vnm, &range, template_index, hw_if_index);
  t_async_enable_1 = clib_cpu_time_now ();
  if (rv)
    return clib_error_return (0, "vnet_flow_async_enable failed: %d", rv);

  vlib_cli_output (vm, "Enabled %u async flows on hardware", n_flows);

  /* === DELETE PHASE === */
  vlib_cli_output (vm, "=== Deleting flows ===");

  t_async_disable_0 = clib_cpu_time_now ();
  rv = vnet_flow_async_disable (vnm, &range, hw_if_index);
  t_async_disable_1 = clib_cpu_time_now ();
  if (rv)
    return clib_error_return (0, "vnet_flow_async_disable failed: %d", rv);

  vlib_cli_output (vm, "Disabled %u async flows from hardware", n_flows);

  t_flow_del_0 = clib_cpu_time_now ();
  for (u32 i = 0; i < n_flows; i++)
    {
      rv = vnet_flow_del (vnm, first_flow_index + i);
      if (rv)
	return clib_error_return (0, "vnet_flow_del failed for flow %u: %d", first_flow_index + i,
				  rv);
    }
  t_flow_del_1 = clib_cpu_time_now ();

  vlib_cli_output (vm, "Deleted %u flows from pool", n_flows);

  t_template_disable_0 = clib_cpu_time_now ();
  rv = vnet_flow_async_template_disable (vnm, template_index, hw_if_index);
  t_template_disable_1 = clib_cpu_time_now ();
  if (rv)
    return clib_error_return (0, "vnet_flow_async_template_disable failed: %d", rv);

  vlib_cli_output (vm, "Template disabled on interface");

  t_template_del_0 = clib_cpu_time_now ();
  rv = vnet_flow_del_async_template (vnm, template_index);
  t_template_del_1 = clib_cpu_time_now ();
  if (rv)
    return clib_error_return (0, "vnet_flow_del_async_template failed: %d", rv);

  vlib_cli_output (vm, "Template deleted");

  /* === TIMING RESULTS === */
  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "=== Timing Results (%u flows) ===", n_flows);
  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "ADD operations:");
  vlib_cli_output (vm, "  Template add:      %10.6f sec",
		   (f64) (t_template_add_1 - t_template_add_0) / clocks_per_second);
  vlib_cli_output (vm, "  Template enable:   %10.6f sec",
		   (f64) (t_template_enable_1 - t_template_enable_0) / clocks_per_second);
  vlib_cli_output (vm, "  Flow add (pool):   %10.6f sec, %8.2f cycles/flow, %8.2f Kflows/sec",
		   (f64) (t_flow_add_1 - t_flow_add_0) / clocks_per_second,
		   (f64) (t_flow_add_1 - t_flow_add_0) / n_flows,
		   (f64) n_flows * clocks_per_second / (t_flow_add_1 - t_flow_add_0) / 1000.0);
  vlib_cli_output (vm, "  Async enable (hw): %10.6f sec, %8.2f cycles/flow, %8.2f Kflows/sec",
		   (f64) (t_async_enable_1 - t_async_enable_0) / clocks_per_second,
		   (f64) (t_async_enable_1 - t_async_enable_0) / n_flows,
		   (f64) n_flows * clocks_per_second / (t_async_enable_1 - t_async_enable_0) /
		     1000.0);
  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "DELETE operations:");
  vlib_cli_output (vm, "  Async disable (hw): %9.6f sec, %8.2f cycles/flow, %8.2f Kflows/sec",
		   (f64) (t_async_disable_1 - t_async_disable_0) / clocks_per_second,
		   (f64) (t_async_disable_1 - t_async_disable_0) / n_flows,
		   (f64) n_flows * clocks_per_second / (t_async_disable_1 - t_async_disable_0) /
		     1000.0);
  vlib_cli_output (vm, "  Flow del (pool):    %9.6f sec, %8.2f cycles/flow, %8.2f Kflows/sec",
		   (f64) (t_flow_del_1 - t_flow_del_0) / clocks_per_second,
		   (f64) (t_flow_del_1 - t_flow_del_0) / n_flows,
		   (f64) n_flows * clocks_per_second / (t_flow_del_1 - t_flow_del_0) / 1000.0);
  vlib_cli_output (vm, "  Template disable:   %9.6f sec",
		   (f64) (t_template_disable_1 - t_template_disable_0) / clocks_per_second);
  vlib_cli_output (vm, "  Template del:       %9.6f sec",
		   (f64) (t_template_del_1 - t_template_del_0) / clocks_per_second);

  return 0;
}

VLIB_CLI_COMMAND (test_flow_cmd, static) = {
  .path = "test flow",
  .short_help = "test flow <interface> <n-flows>",
  .function = test_flow_command_fn,
};

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/flow/flow.h>
#include <sfdp_services/base/verdict-testbench/verdict_testbench.h>

verdict_testbench_main_t verdict_testbench_main;

clib_error_t *
verdict_testbench_enable (verdict_testbench_main_t *vt, u32 tx_sw_if_index, u32 rx_sw_if_index,
			  u8 enable_counters)
{
  vnet_main_t *vnm = vnet_get_main ();
  sfdp_main_t *sfdp = &sfdp_main;
  vnet_flow_t flow_template = {};
  u32 template_index;
  u32 tx_hw_if_index;
  u32 rx_hw_if_index;
  u32 max_flows;
  int rv;

  if (vt->is_enabled)
    return clib_error_return (0, "already enabled");

  tx_hw_if_index = vnet_get_sw_interface (vnm, tx_sw_if_index)->hw_if_index;
  rx_hw_if_index =
    (rx_sw_if_index != ~0) ? vnet_get_sw_interface (vnm, rx_sw_if_index)->hw_if_index : ~0;
  max_flows = 1ULL << sfdp->log2_sessions;

  flow_template.type = VNET_FLOW_TYPE_IP4_N_TUPLE;
  flow_template.actions = VNET_FLOW_ACTION_STEER_TO_PORT;
  if (enable_counters)
    flow_template.actions |= VNET_FLOW_ACTION_COUNT;
  flow_template.steer_to_hw_if_index = tx_hw_if_index;
  flow_template.steer_from_hw_if_index =
    rx_hw_if_index; /* If rx_hw_if_index is ~0 / invalid, then we will accept from all incoming
		       hw_if_index*/
  flow_template.pattern.ip4_n_tuple.src_addr.mask.as_u32 = ~0;
  flow_template.pattern.ip4_n_tuple.dst_addr.mask.as_u32 = ~0;
  flow_template.pattern.ip4_n_tuple.src_port.mask = 0xFFFF;
  flow_template.pattern.ip4_n_tuple.dst_port.mask = 0xFFFF;
  flow_template.pattern.ip4_n_tuple.protocol.mask = 0xFF;

  rv = vnet_flow_template_add (vnm, &flow_template, &template_index);
  if (rv)
    return clib_error_return (0, "flow template add failed: %d", rv);

  rv = vnet_flow_template_enable (vnm, template_index, tx_hw_if_index, max_flows);
  if (rv)
    {
      vnet_flow_template_del (vnm, template_index);
      return clib_error_return (0, "flow template enable failed: %d", rv);
    }

  vt->verdict_template_index = template_index;
  vt->tx_sw_if_index = tx_sw_if_index;
  vt->rx_sw_if_index = rx_sw_if_index;
  vt->hw_if_index = tx_hw_if_index;
  vt->tx_hw_if_index = tx_hw_if_index;
  vt->template_on_hw = 1;
  vt->is_enabled = 1;
  vt->enable_counters = enable_counters;

  return 0;
}

clib_error_t *
verdict_testbench_disable (verdict_testbench_main_t *vt)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (!vt->is_enabled)
    return clib_error_return (0, "not enabled");

  if (vt->template_on_hw)
    {
      vnet_flow_template_disable (vnm, vt->verdict_template_index);
      vt->template_on_hw = 0;
    }
  vnet_flow_template_del (vnm, vt->verdict_template_index);

  vt->is_enabled = 0;
  vt->rx_sw_if_index = ~0;
  vt->tx_sw_if_index = ~0;
  vt->hw_if_index = ~0;
  vt->tx_hw_if_index = ~0;
  vt->verdict_template_index = ~0;

  return 0;
}

static clib_error_t *
verdict_testbench_init (vlib_main_t *vm)
{
  verdict_testbench_main_t *vt = &verdict_testbench_main;

  vt->rx_sw_if_index = ~0;
  vt->tx_sw_if_index = ~0;
  vt->hw_if_index = ~0;
  vt->tx_hw_if_index = ~0;
  vt->verdict_template_index = ~0;
  vt->is_enabled = 0;
  vt->template_on_hw = 0;

  return 0;
}

VLIB_INIT_FUNCTION (verdict_testbench_init);

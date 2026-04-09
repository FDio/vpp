/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/flow/flow.h>
#include <sfdp_services/base/verdict-testbench/verdict_testbench.h>

verdict_testbench_main_t verdict_testbench_main;

static clib_error_t *
vt_create_template (vnet_main_t *vnm, vnet_flow_t *flow_template, ip_protocol_t proto,
		    u32 tx_hw_if_index, u32 max_flows, u32 *template_index)
{
  int rv;

  flow_template->pattern.ip4_n_tuple.protocol.prot = proto;
  rv = vnet_flow_template_add (vnm, flow_template, template_index);
  if (rv)
    return clib_error_return (0, "%s flow template add failed: %d",
			      proto == IP_PROTOCOL_UDP ? "UDP" : "TCP", rv);

  rv = vnet_flow_template_enable (vnm, *template_index, tx_hw_if_index, max_flows);
  if (rv)
    {
      vnet_flow_template_del (vnm, *template_index);
      *template_index = ~0;
      return clib_error_return (0, "%s flow template enable failed: %d",
				proto == IP_PROTOCOL_UDP ? "UDP" : "TCP", rv);
    }

  return 0;
}

clib_error_t *
verdict_testbench_enable (verdict_testbench_main_t *vt, u32 tx_sw_if_index, u32 rx_sw_if_index,
			  u8 enable_counters, u8 protos)
{
  vnet_main_t *vnm = vnet_get_main ();
  sfdp_main_t *sfdp = &sfdp_main;
  vnet_flow_t flow_template = {};
  clib_error_t *err = 0;
  u32 tx_hw_if_index;
  u32 rx_hw_if_index;
  u32 max_flows;

  if (vt->is_enabled)
    return clib_error_return (0, "already enabled");

  if (!(protos & (VT_PROTO_UDP | VT_PROTO_TCP)))
    return clib_error_return (0, "at least one protocol (udp/tcp) must be specified");

  tx_hw_if_index = vnet_get_sw_interface (vnm, tx_sw_if_index)->hw_if_index;
  rx_hw_if_index =
    (rx_sw_if_index != ~0) ? vnet_get_sw_interface (vnm, rx_sw_if_index)->hw_if_index : ~0;
  /* Each session produces two flow rules (forward + reverse) */
  max_flows = 2ULL << sfdp->log2_sessions;

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

  if (protos & VT_PROTO_UDP)
    {
      err = vt_create_template (vnm, &flow_template, IP_PROTOCOL_UDP, tx_hw_if_index, max_flows,
				&vt->udp_template_index);
      if (err)
	return err;
    }

  if (protos & VT_PROTO_TCP)
    {
      err = vt_create_template (vnm, &flow_template, IP_PROTOCOL_TCP, tx_hw_if_index, max_flows,
				&vt->tcp_template_index);
      if (err)
	{
	  if (protos & VT_PROTO_UDP)
	    {
	      vnet_flow_template_disable (vnm, vt->udp_template_index);
	      vnet_flow_template_del (vnm, vt->udp_template_index);
	      vt->udp_template_index = ~0;
	    }
	  return err;
	}
    }

  vt->enabled_protos = protos;
  vt->tx_sw_if_index = tx_sw_if_index;
  vt->rx_sw_if_index = rx_sw_if_index;
  vt->hw_if_index = tx_hw_if_index;
  vt->tx_hw_if_index = tx_hw_if_index;
  vt->templates_on_hw = 1;
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

  if (vt->templates_on_hw)
    {
      if (vt->enabled_protos & VT_PROTO_UDP)
	vnet_flow_template_disable (vnm, vt->udp_template_index);
      if (vt->enabled_protos & VT_PROTO_TCP)
	vnet_flow_template_disable (vnm, vt->tcp_template_index);
      vt->templates_on_hw = 0;
    }

  if (vt->enabled_protos & VT_PROTO_UDP)
    vnet_flow_template_del (vnm, vt->udp_template_index);
  if (vt->enabled_protos & VT_PROTO_TCP)
    vnet_flow_template_del (vnm, vt->tcp_template_index);

  vt->is_enabled = 0;
  vt->enabled_protos = 0;
  vt->rx_sw_if_index = ~0;
  vt->tx_sw_if_index = ~0;
  vt->hw_if_index = ~0;
  vt->tx_hw_if_index = ~0;
  vt->udp_template_index = ~0;
  vt->tcp_template_index = ~0;

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
  vt->udp_template_index = ~0;
  vt->tcp_template_index = ~0;
  vt->is_enabled = 0;
  vt->templates_on_hw = 0;
  vt->enabled_protos = 0;

  return 0;
}

VLIB_INIT_FUNCTION (verdict_testbench_init);

// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/service.h>
#include <vnet/feature/feature.h>
#include "node.h"

// Graph node for VXLAN and Geneve tunnel decap
VLIB_NODE_FN(vcdp_tunnel_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_tunnel_input_node_inline(vm, node, frame);
}

VLIB_REGISTER_NODE(vcdp_tunnel_input_node) = {
  .name = "vcdp-tunnel-input",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_tunnel_decap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = VCDP_TUNNEL_INPUT_N_ERROR,
  .error_counters = vcdp_tunnel_input_error_counters,
  .n_next_nodes = VCDP_TUNNEL_INPUT_N_NEXT,
  .next_nodes =
    {
      [VCDP_TUNNEL_INPUT_NEXT_DROP] = "error-drop",
      [VCDP_TUNNEL_INPUT_NEXT_IP4_LOOKUP] = "vcdp-lookup-ip4",
    },
};

/* Hook up features */
VNET_FEATURE_INIT(vcdp_tunnel_input, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "vcdp-tunnel-input",
  .runs_after = VNET_FEATURES("ip4-sv-reassembly-feature"), // TODO: Needed?
};

VLIB_NODE_FN(vcdp_tunnel_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_tunnel_output_node_inline(vm, node, frame);
}

VLIB_REGISTER_NODE(vcdp_tunnel_output_node) = {
  .name = "vcdp-tunnel-output",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_tunnel_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_TUNNEL_OUTPUT_N_ERROR,
  .error_counters = vcdp_tunnel_output_error_counters,
  .n_next_nodes = VCDP_TUNNEL_OUTPUT_N_NEXT,
  .next_nodes =
    {
      [VCDP_TUNNEL_OUTPUT_NEXT_DROP] = "error-drop",
      [VCDP_TUNNEL_OUTPUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [VCDP_TUNNEL_OUTPUT_NEXT_ICMP_ERROR] = "vcdp-icmp-error",
    }

};

VCDP_SERVICE_DEFINE(vcdp_tunnel_output) = {
  .node_name = "vcdp-tunnel-output",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle", "vcdp-tcp-check"),
  .is_terminal = 1};
/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/ip4_source_check.c: IP v4 check source address (unicast RPF check) */

#include <urpf/urpf.h>
#include <urpf/urpf_dp.h>

static char *ip6_urpf_error_strings[] = {
#define _(a, b) b,
  foreach_urpf_error
#undef _
};

VLIB_NODE_FN (ip6_rx_urpf_loose) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return (urpf_inline (vm, node, frame, AF_IP6, VLIB_RX, URPF_MODE_LOOSE));
}

VLIB_NODE_FN (ip6_rx_urpf_strict) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (urpf_inline (vm, node, frame, AF_IP6, VLIB_RX, URPF_MODE_STRICT));
}

VLIB_NODE_FN (ip6_tx_urpf_loose) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return (urpf_inline (vm, node, frame, AF_IP6, VLIB_TX, URPF_MODE_LOOSE));
}

VLIB_NODE_FN (ip6_tx_urpf_strict) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (urpf_inline (vm, node, frame, AF_IP6, VLIB_TX, URPF_MODE_STRICT));
}

VLIB_REGISTER_NODE (ip6_rx_urpf_loose) = {
  .name = "ip6-rx-urpf-loose",
  .vector_size = sizeof (u32),

  .n_next_nodes = URPF_N_NEXT,
  .next_nodes = {
    [URPF_NEXT_DROP] = "ip6-drop",
  },
  .n_errors = ARRAY_LEN (ip6_urpf_error_strings),
  .error_strings = ip6_urpf_error_strings,

  .format_buffer = format_ip6_header,
  .format_trace = format_urpf_trace,
};

VLIB_REGISTER_NODE (ip6_rx_urpf_strict) = {
  .name = "ip6-rx-urpf-strict",
  .vector_size = sizeof (u32),

  .n_next_nodes = URPF_N_NEXT,
  .next_nodes = {
    [URPF_NEXT_DROP] = "ip6-drop",
  },
  .n_errors = ARRAY_LEN (ip6_urpf_error_strings),
  .error_strings = ip6_urpf_error_strings,

  .format_buffer = format_ip6_header,
  .format_trace = format_urpf_trace,
};

VLIB_REGISTER_NODE (ip6_tx_urpf_loose) = {
  .name = "ip6-tx-urpf-loose",
  .vector_size = sizeof (u32),

  .n_next_nodes = URPF_N_NEXT,
  .next_nodes = {
    [URPF_NEXT_DROP] = "ip6-drop",
  },
  .n_errors = ARRAY_LEN (ip6_urpf_error_strings),
  .error_strings = ip6_urpf_error_strings,

  .format_buffer = format_ip6_header,
  .format_trace = format_urpf_trace,
};

VLIB_REGISTER_NODE (ip6_tx_urpf_strict) = {
  .name = "ip6-tx-urpf-strict",
  .vector_size = sizeof (u32),

  .n_next_nodes = URPF_N_NEXT,
  .next_nodes = {
    [URPF_NEXT_DROP] = "ip6-drop",
  },
  .n_errors = ARRAY_LEN (ip6_urpf_error_strings),
  .error_strings = ip6_urpf_error_strings,

  .format_buffer = format_ip6_header,
  .format_trace = format_urpf_trace,
};

VNET_FEATURE_INIT (ip6_rx_urpf_loose_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-rx-urpf-loose",
  .runs_before = VNET_FEATURES ("ip6-rx-urpf-strict"),
};

VNET_FEATURE_INIT (ip6_rx_urpf_strict_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-rx-urpf-strict",
  .runs_before = VNET_FEATURES ("ip6-policer-classify"),
};

VNET_FEATURE_INIT (ip6_tx_urpf_loose_feat, static) =
{
  .arc_name = "ip6-output",
  .node_name = "ip6-tx-urpf-loose",
};

VNET_FEATURE_INIT (ip6_tx_urpf_strict_feat, static) = {
  .arc_name = "ip6-output",
  .node_name = "ip6-tx-urpf-strict",
};

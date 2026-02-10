/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_punt_drop.h>

VNET_FEATURE_ARC_INIT (ip6_punt) =
{
  .arc_name  = "ip6-punt",
  .start_nodes = VNET_FEATURES ("ip6-punt"),
};

VNET_FEATURE_ARC_INIT (ip6_drop) =
{
  .arc_name  = "ip6-drop",
  .start_nodes = VNET_FEATURES ("ip6-drop", "ip6-not-enabled"),
};

VLIB_NODE_FN (ip6_drop_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip6_drop.feature_arc_index);

}

VLIB_NODE_FN (ip6_not_enabled_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip6_drop.feature_arc_index);

}

VLIB_NODE_FN (ip6_punt_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip6_punt.feature_arc_index);
}

VLIB_REGISTER_NODE (ip6_drop_node) =
{
  .name = "ip6-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ip6_not_enabled_node) = {
  .name = "ip6-not-enabled",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .sibling_of = "ip6-drop",
};

VLIB_REGISTER_NODE (ip6_punt_node) =
{
  .name = "ip6-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-punt",
  },
};

VNET_FEATURE_INIT (ip6_punt_end_of_arc, static) = {
  .arc_name = "ip6-punt",
  .node_name = "error-punt",
  .runs_before = 0, /* not before any other features */
};

VNET_FEATURE_INIT (ip6_drop_end_of_arc, static) = {
  .arc_name = "ip6-drop",
  .node_name = "error-drop",
  .runs_before = 0, /* not before any other features */
};

#define foreach_ip6_punt_redirect_error         \
_(DROP, "ip6 punt redirect drop")

typedef enum
{
#define _(sym,str) IP6_PUNT_REDIRECT_ERROR_##sym,
  foreach_ip6_punt_redirect_error
#undef _
    IP6_PUNT_REDIRECT_N_ERROR,
} ip6_punt_redirect_error_t;

static char *ip6_punt_redirect_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_punt_redirect_error
#undef _
};

VLIB_NODE_FN (ip6_punt_redirect_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
{
  return (ip_punt_redirect (vm, node, frame,
			    vnet_feat_arc_ip6_punt.feature_arc_index,
			    FIB_PROTOCOL_IP6));
}

VLIB_REGISTER_NODE (ip6_punt_redirect_node) = {
  .name = "ip6-punt-redirect",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_PUNT_REDIRECT_N_NEXT,
  .format_trace = format_ip_punt_redirect_trace,
  .n_errors = ARRAY_LEN(ip6_punt_redirect_error_strings),
  .error_strings = ip6_punt_redirect_error_strings,

  /* edit / add dispositions here */
  .next_nodes = {
    [IP_PUNT_REDIRECT_NEXT_DROP] = "ip6-drop",
    [IP_PUNT_REDIRECT_NEXT_TX] = "ip6-rewrite",
    [IP_PUNT_REDIRECT_NEXT_ARP] = "ip6-discover-neighbor",
  },
};

VNET_FEATURE_INIT (ip6_punt_redirect_node, static) = {
  .arc_name = "ip6-punt",
  .node_name = "ip6-punt-redirect",
  .runs_before = VNET_FEATURES("error-punt")
};

#ifndef CLIB_MARCH_VARIANT

static u32 ip6_punt_redirect_enable_counts;

void
ip6_punt_redirect_add_paths (u32 rx_sw_if_index,
			     const fib_route_path_t *rpaths)
{
  ip_punt_redirect_add (FIB_PROTOCOL_IP6,
			rx_sw_if_index,
			FIB_FORW_CHAIN_TYPE_UNICAST_IP6, rpaths);

  if (1 == ++ip6_punt_redirect_enable_counts)
    vnet_feature_enable_disable ("ip6-punt", "ip6-punt-redirect", 0, 1, 0, 0);
}

void
ip6_punt_redirect_del (u32 rx_sw_if_index)
{
  ASSERT (ip6_punt_redirect_enable_counts);
  if (0 == --ip6_punt_redirect_enable_counts)
    vnet_feature_enable_disable ("ip6-punt", "ip6-punt-redirect", 0, 0, 0, 0);

  ip_punt_redirect_del (FIB_PROTOCOL_IP6, rx_sw_if_index);
}
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
ip6_punt_redirect_cmd (vlib_main_t * vm,
		       unformat_input_t * main_input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_route_path_t *rpaths = NULL, rpath;
  dpo_proto_t payload_proto = DPO_PROTO_IP6;
  clib_error_t *error = 0;
  u32 rx_sw_if_index = ~0;
  vnet_main_t *vnm;
  u8 is_add;

  is_add = 1;
  vnm = vnet_get_main ();

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "rx all"))
	rx_sw_if_index = 0;
      else if (unformat (line_input, "rx %U",
			 unformat_vnet_sw_interface, vnm, &rx_sw_if_index))
	;
      else if (unformat (line_input, "via %U",
			 unformat_fib_route_path, &rpath, &payload_proto))
	vec_add1 (rpaths, rpath);
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == rx_sw_if_index)
    {
      error = unformat_parse_error (line_input);
      goto done;
    }

  if (is_add)
    {
      if (vec_len (rpaths))
	ip6_punt_redirect_add_paths (rx_sw_if_index, rpaths);
    }
  else
    {
      ip6_punt_redirect_del (rx_sw_if_index);
    }

done:
  vec_free (rpaths);
  unformat_free (line_input);
  return (error);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{set ip punt policer <INDEX>}
 ?*/
VLIB_CLI_COMMAND (ip6_punt_redirect_command, static) =
{
  .path = "ip6 punt redirect",
  .function = ip6_punt_redirect_cmd,
  .short_help = "ip6 punt redirect [add|del] rx [<interface>|all] via [<nh>] <tx_interface>",
};

#ifndef CLIB_MARCH_VARIANT

#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
ip6_punt_redirect_show_cmd (vlib_main_t * vm,
			    unformat_input_t * main_input,
			    vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "%U", format_ip_punt_redirect, FIB_PROTOCOL_IP6);

  return (NULL);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{set ip punt policer <INDEX>}
 ?*/
VLIB_CLI_COMMAND (show_ip6_punt_redirect_command, static) = {
  .path = "show ip6 punt redirect",
  .function = ip6_punt_redirect_show_cmd,
  .short_help = "show ip6 punt redirect",
  .is_mp_safe = 1,
};

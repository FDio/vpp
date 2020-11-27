/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_punt_drop.h>
#include <vnet/policer/policer.h>
#include <vnet/policer/police_inlines.h>

/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (ip4_punt) =
{
  .arc_name  = "ip4-punt",
  .start_nodes = VNET_FEATURES ("ip4-punt"),
};

VNET_FEATURE_ARC_INIT (ip4_drop) =
{
  .arc_name  = "ip4-drop",
  .start_nodes = VNET_FEATURES ("ip4-drop", "ip4-not-enabled"),
};
/* *INDENT-ON* */

extern ip_punt_policer_t ip4_punt_policer_cfg;

#ifndef CLIB_MARCH_VARIANT
u8 *
format_ip_punt_policer_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_punt_policer_trace_t *t = va_arg (*args, ip_punt_policer_trace_t *);

  s = format (s, "policer_index %d next %d", t->policer_index, t->next);
  return s;
}

ip_punt_policer_t ip4_punt_policer_cfg = {
  .policer_index = ~0,
};
#endif /* CLIB_MARCH_VARIANT */

static char *ip4_punt_policer_error_strings[] = {
#define _(sym,string) string,
  foreach_ip_punt_policer_error
#undef _
};

VLIB_NODE_FN (ip4_punt_policer_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return (ip_punt_policer (vm, node, frame,
			   vnet_feat_arc_ip4_punt.feature_arc_index,
			   ip4_punt_policer_cfg.policer_index));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_punt_policer_node) = {
  .name = "ip4-punt-policer",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_PUNT_POLICER_N_NEXT,
  .format_trace = format_ip_punt_policer_trace,
  .n_errors = ARRAY_LEN(ip4_punt_policer_error_strings),
  .error_strings = ip4_punt_policer_error_strings,

  .next_nodes = {
    [IP_PUNT_POLICER_NEXT_DROP] = "ip4-drop",
  },
};

VNET_FEATURE_INIT (ip4_punt_policer_node) = {
  .arc_name = "ip4-punt",
  .node_name = "ip4-punt-policer",
  .runs_before = VNET_FEATURES("ip4-punt-redirect"),
};
/* *INDENT-ON* */


#define foreach_ip4_punt_redirect_error         \
_(DROP, "ip4 punt redirect drop")

typedef enum
{
#define _(sym,str) IP4_PUNT_REDIRECT_ERROR_##sym,
  foreach_ip4_punt_redirect_error
#undef _
    IP4_PUNT_REDIRECT_N_ERROR,
} ip4_punt_redirect_error_t;

static char *ip4_punt_redirect_error_strings[] = {
#define _(sym,string) string,
  foreach_ip4_punt_redirect_error
#undef _
};

VLIB_NODE_FN (ip4_punt_redirect_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
{
  return (ip_punt_redirect (vm, node, frame,
			    vnet_feat_arc_ip4_punt.feature_arc_index,
			    FIB_PROTOCOL_IP4));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_punt_redirect_node) = {
  .name = "ip4-punt-redirect",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_PUNT_REDIRECT_N_NEXT,
  .format_trace = format_ip_punt_redirect_trace,
  .n_errors = ARRAY_LEN(ip4_punt_redirect_error_strings),
  .error_strings = ip4_punt_redirect_error_strings,

  /* edit / add dispositions here */
  .next_nodes = {
    [IP_PUNT_REDIRECT_NEXT_DROP] = "ip4-drop",
    [IP_PUNT_REDIRECT_NEXT_TX] = "ip4-rewrite",
    [IP_PUNT_REDIRECT_NEXT_ARP] = "ip4-arp",
  },
};

VNET_FEATURE_INIT (ip4_punt_redirect_node, static) = {
  .arc_name = "ip4-punt",
  .node_name = "ip4-punt-redirect",
  .runs_before = VNET_FEATURES("error-punt"),
};
/* *INDENT-ON* */

VLIB_NODE_FN (ip4_drop_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip4_drop.feature_arc_index);

}

VLIB_NODE_FN (ip4_not_enabled_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip4_drop.feature_arc_index);
}

static uword
ip4_punt (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip4_punt.feature_arc_index);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_drop_node) =
{
  .name = "ip4-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ip4_not_enabled_node) =
{
  .name = "ip4-not-enabled",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .sibling_of = "ip4-drop",
};

VLIB_REGISTER_NODE (ip4_punt_node) =
{
  .function = ip4_punt,
  .name = "ip4-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-punt",
  },
};

VNET_FEATURE_INIT (ip4_punt_end_of_arc, static) = {
  .arc_name = "ip4-punt",
  .node_name = "error-punt",
  .runs_before = 0, /* not before any other features */
};

VNET_FEATURE_INIT (ip4_drop_end_of_arc, static) = {
  .arc_name = "ip4-drop",
  .node_name = "error-drop",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON */

#ifndef CLIB_MARCH_VARIANT
void
ip4_punt_policer_add_del (u8 is_add, u32 policer_index)
{
  ip4_punt_policer_cfg.policer_index = policer_index;

  vnet_feature_enable_disable ("ip4-punt", "ip4-punt-policer",
                               0, is_add, 0, 0);
}
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
ip4_punt_police_cmd (vlib_main_t * vm,
                     unformat_input_t * main_input,
                     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 policer_index;
  u8 is_add = 1;

  policer_index = ~0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &policer_index))
        ;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "add"))
        is_add = 1;
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  if (is_add && ~0 == policer_index)
  {
      error = clib_error_return (0, "expected policer index `%U'",
                                 format_unformat_error, line_input);
      goto done;
  }
  if (!is_add)
      policer_index = ~0;

  ip4_punt_policer_add_del(is_add, policer_index);

done:
  unformat_free (line_input);
  return (error);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{set ip punt policer <INDEX>}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip4_punt_policer_command, static) =
{
  .path = "ip punt policer",
  .function = ip4_punt_police_cmd,
  .short_help = "ip punt policer [add|del] <index>",
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT

void
ip4_punt_redirect_add (u32 rx_sw_if_index,
		       u32 tx_sw_if_index, ip46_address_t * nh)
{
  /* *INDENT-OFF* */
  fib_route_path_t *rpaths = NULL, rpath = {
    .frp_proto = DPO_PROTO_IP4,
    .frp_addr = *nh,
    .frp_sw_if_index = tx_sw_if_index,
    .frp_weight = 1,
    .frp_fib_index = ~0,
  };
  /* *INDENT-ON* */

  vec_add1 (rpaths, rpath);

  ip4_punt_redirect_add_paths (rx_sw_if_index, rpaths);

  vec_free (rpaths);
}

void
ip4_punt_redirect_add_paths (u32 rx_sw_if_index, fib_route_path_t * rpaths)
{
  ip_punt_redirect_add (FIB_PROTOCOL_IP4,
			rx_sw_if_index,
			FIB_FORW_CHAIN_TYPE_UNICAST_IP4, rpaths);

  vnet_feature_enable_disable ("ip4-punt", "ip4-punt-redirect", 0, 1, 0, 0);
}

void
ip4_punt_redirect_del (u32 rx_sw_if_index)
{
  vnet_feature_enable_disable ("ip4-punt", "ip4-punt-redirect", 0, 0, 0, 0);

  ip_punt_redirect_del (FIB_PROTOCOL_IP4, rx_sw_if_index);
}
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
ip4_punt_redirect_cmd (vlib_main_t * vm,
		       unformat_input_t * main_input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t nh = { 0 };
  clib_error_t *error = 0;
  u32 rx_sw_if_index = ~0;
  u32 tx_sw_if_index = ~0;
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
	rx_sw_if_index = ~0;
      else if (unformat (line_input, "rx %U",
			 unformat_vnet_sw_interface, vnm, &rx_sw_if_index))
	;
      else if (unformat (line_input, "via %U %U",
			 unformat_ip4_address, &nh.ip4,
			 unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
	;
      else if (unformat (line_input, "via %U",
			 unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
	;
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
      ip4_punt_redirect_add (rx_sw_if_index, tx_sw_if_index, &nh);
    }
  else
    {
      ip4_punt_redirect_del (rx_sw_if_index);
    }

done:
  unformat_free (line_input);
  return (error);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{set ip punt policer}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip4_punt_redirect_command, static) =
{
  .path = "ip punt redirect",
  .function = ip4_punt_redirect_cmd,
  .short_help = "ip punt redirect [add|del] rx [<interface>|all] via [<nh>] <tx_interface>",
};
/* *INDENT-ON* */

static clib_error_t *
ip4_punt_redirect_show_cmd (vlib_main_t * vm,
			    unformat_input_t * main_input,
			    vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "%U", format_ip_punt_redirect, FIB_PROTOCOL_IP4);

  return (NULL);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{set ip punt redierect}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip4_punt_redirect_command, static) =
{
  .path = "show ip punt redirect",
  .function = ip4_punt_redirect_show_cmd,
  .short_help = "show ip punt redirect",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

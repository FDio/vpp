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
VNET_FEATURE_ARC_INIT (ip6_punt) =
{
  .arc_name  = "ip6-punt",
  .start_nodes = VNET_FEATURES ("ip6-punt"),
};

VNET_FEATURE_ARC_INIT (ip6_drop) =
{
  .arc_name  = "ip6-drop",
  .start_nodes = VNET_FEATURES ("ip6-drop"),
};
/* *INDENT-ON* */

ip_punt_policer_t ip6_punt_policer_cfg;

static char *ip6_punt_policer_error_strings[] = {
#define _(sym,string) string,
  foreach_ip_punt_policer_error
#undef _
};

static uword
ip6_punt_policer (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip_punt_policer (vm, node, frame,
			   vnet_feat_arc_ip6_punt.feature_arc_index,
			   ip6_punt_policer_cfg.policer_index));
}


/* *INDENT-OFF* */

VLIB_REGISTER_NODE (ip6_punt_policer_node, static) = {
  .function = ip6_punt_policer,
  .name = "ip6-punt-policer",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_PUNT_POLICER_N_NEXT,
  .format_trace = format_ip_punt_policer_trace,
  .n_errors = ARRAY_LEN(ip6_punt_policer_error_strings),
  .error_strings = ip6_punt_policer_error_strings,

  /* edit / add dispositions here */
  .next_nodes = {
    [IP_PUNT_POLICER_NEXT_DROP] = "ip6-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_punt_policer_node,
                              ip6_punt_policer);

VNET_FEATURE_INIT (ip6_punt_policer_node, static) = {
  .arc_name = "ip6-punt",
  .node_name = "ip6-punt-policer",
  .runs_before = VNET_FEATURES("ip6-punt-redirect")
};
/* *INDENT-ON* */

static uword
ip6_drop (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip6_drop.feature_arc_index);

}

static uword
ip6_punt (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip6_punt.feature_arc_index);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_drop_node, static) =
{
  .function = ip6_drop,
  .name = "ip6-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_drop_node, ip6_drop);

VLIB_REGISTER_NODE (ip6_punt_node, static) =
{
  .function = ip6_punt,
  .name = "ip6-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-punt",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_punt_node, ip6_punt);

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
/* *INDENT-ON */

void
ip6_punt_policer_add_del (u8 is_add, u32 policer_index)
{
  ip6_punt_policer_cfg.policer_index = policer_index;

  vnet_feature_enable_disable ("ip6-punt", "ip6-punt-policer",
                               0, is_add, 0, 0);
}

static clib_error_t *
ip6_punt_police_cmd (vlib_main_t * vm,
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

  ip6_punt_policer_add_del(is_add, policer_index);

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
VLIB_CLI_COMMAND (ip6_punt_policer_command, static) =
{
  .path = "ip6 punt policer",
  .function = ip6_punt_police_cmd,
  .short_help = "ip6 punt policer [add|del] <index>",
};
/* *INDENT-ON* */

ip_punt_redirect_t ip6_punt_redirect_cfg = {
  .any_rx_sw_if_index = {
			 .tx_sw_if_index = ~0,
			 }
  ,
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

static uword
ip6_punt_redirect (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip_punt_redirect (vm, node, frame,
			    vnet_feat_arc_ip6_punt.feature_arc_index,
			    &ip6_punt_redirect_cfg));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_punt_redirect_node, static) = {
  .function = ip6_punt_redirect,
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

VLIB_NODE_FUNCTION_MULTIARCH (ip6_punt_redirect_node,
                              ip6_punt_redirect);

VNET_FEATURE_INIT (ip6_punt_redirect_node, static) = {
  .arc_name = "ip6-punt",
  .node_name = "ip6-punt-redirect",
  .runs_before = VNET_FEATURES("error-punt")
};
/* *INDENT-ON* */

void
ip6_punt_redirect_add (u32 rx_sw_if_index,
		       u32 tx_sw_if_index, ip46_address_t * nh)
{
  ip_punt_redirect_rx_t rx = {
    .tx_sw_if_index = tx_sw_if_index,
    .nh = *nh,
  };

  ip_punt_redirect_add (&ip6_punt_redirect_cfg,
			rx_sw_if_index, &rx, FIB_PROTOCOL_IP6, VNET_LINK_IP6);

  vnet_feature_enable_disable ("ip6-punt", "ip6-punt-redirect", 0, 1, 0, 0);
}

void
ip6_punt_redirect_del (u32 rx_sw_if_index)
{
  vnet_feature_enable_disable ("ip6-punt", "ip6-punt-redirect", 0, 0, 0, 0);

  ip_punt_redirect_del (&ip6_punt_redirect_cfg, rx_sw_if_index);
}

static clib_error_t *
ip6_punt_redirect_cmd (vlib_main_t * vm,
		       unformat_input_t * main_input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  ip46_address_t nh;
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
			 unformat_ip6_address,
			 &nh.ip6,
			 unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
	;
      else if (unformat (line_input, "via %U",
			 unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
	memset (&nh, 0, sizeof (nh));
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (is_add)
    ip6_punt_redirect_add (rx_sw_if_index, tx_sw_if_index, &nh);
  else
    ip6_punt_redirect_del (rx_sw_if_index);

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
VLIB_CLI_COMMAND (ip6_punt_redirect_command, static) =
{
  .path = "ip6 punt redirect",
  .function = ip6_punt_redirect_cmd,
  .short_help = "ip6 punt redirect [add|del] rx [<interface>|all] via [<nh>] <tx_interface>",
};
/* *INDENT-ON* */

static clib_error_t *
ip6_punt_redirect_show_cmd (vlib_main_t * vm,
			    unformat_input_t * main_input,
			    vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "%U", format_ip_punt_redirect, &ip6_punt_redirect_cfg);

  return (NULL);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{set ip punt policer <INDEX>}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip6_punt_redirect_command, static) =
{
  .path = "show ip6 punt redirect",
  .function = ip6_punt_redirect_show_cmd,
  .short_help = "show ip6 punt redirect [add|del] rx [<interface>|all] via [<nh>] <tx_interface>",
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

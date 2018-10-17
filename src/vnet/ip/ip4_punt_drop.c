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

static char *ip4_punt_policer_error_strings[] = {
#define _(sym,string) string,
  foreach_ip_punt_policer_error
#undef _
};

static uword
ip4_punt_policer (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip_punt_policer (vm, node, frame,
			   vnet_feat_arc_ip4_punt.feature_arc_index,
			   ip4_punt_policer_cfg.policer_index));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_punt_policer_node, static) = {
  .function = ip4_punt_policer,
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

VLIB_NODE_FUNCTION_MULTIARCH (ip4_punt_policer_node,
                              ip4_punt_policer);

VNET_FEATURE_INIT (ip4_punt_policer_node, static) = {
  .arc_name = "ip4-punt",
  .node_name = "ip4-punt-policer",
  .runs_before = VNET_FEATURES("ip4-punt-redirect"),
};
/* *INDENT-ON* */

u8 *
format_ip_punt_redirect_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_punt_redirect_trace_t *t = va_arg (*args, ip_punt_redirect_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;

  si = vnet_get_sw_interface_safe (vnm, t->redirect.tx_sw_if_index);

  if (NULL != si)
    s = format (s, "via %U on %U using adj:%d",
		format_ip46_address, &t->redirect.nh, IP46_TYPE_ANY,
		format_vnet_sw_interface_name, vnm, si,
		t->redirect.adj_index);
  else
    s = format (s, "via %U on %d using adj:%d",
		format_ip46_address, &t->redirect.nh, IP46_TYPE_ANY,
		t->redirect.tx_sw_if_index, t->redirect.adj_index);

  return s;
}

/* *INDENT-OFF* */
ip_punt_redirect_t ip4_punt_redirect_cfg = {
  .any_rx_sw_if_index = {
    .tx_sw_if_index = ~0,
	.adj_index = ADJ_INDEX_INVALID,
  },
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

static uword
ip4_punt_redirect (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip_punt_redirect (vm, node, frame,
			    vnet_feat_arc_ip4_punt.feature_arc_index,
			    &ip4_punt_redirect_cfg));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_punt_redirect_node, static) = {
  .function = ip4_punt_redirect,
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

VLIB_NODE_FUNCTION_MULTIARCH (ip4_punt_redirect_node,
                              ip4_punt_redirect);

VNET_FEATURE_INIT (ip4_punt_redirect_node, static) = {
  .arc_name = "ip4-punt",
  .node_name = "ip4-punt-redirect",
  .runs_before = VNET_FEATURES("error-punt"),
};
/* *INDENT-ON* */

static uword
ip4_drop (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip4_drop.feature_arc_index);

}

static uword
ip4_not_enabled (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip4_drop.feature_arc_index);
}

static uword
ip4_punt (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return ip_drop_or_punt (vm, node, frame,
			  vnet_feat_arc_ip4_punt.feature_arc_index);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_drop_node, static) =
{
  .function = ip4_drop,
  .name = "ip4-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_drop_node, ip4_drop);

VLIB_REGISTER_NODE (ip4_not_enabled_node, static) =
{
  .function = ip4_not_enabled,
  .name = "ip4-not-enabled",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_not_enabled_node, ip4_not_enabled);

VLIB_REGISTER_NODE (ip4_punt_node, static) =
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

void
ip4_punt_policer_add_del (u8 is_add, u32 policer_index)
{
  ip4_punt_policer_cfg.policer_index = policer_index;

  vnet_feature_enable_disable ("ip4-punt", "ip4-punt-policer",
                               0, is_add, 0, 0);
}

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

/*
 * an uninitalised rx-redirect strcut used to pad the vector
 */
ip_punt_redirect_rx_t uninit_rx_redirect = {
  .tx_sw_if_index = ~0,
  .adj_index = ADJ_INDEX_INVALID,
};

void
ip_punt_redirect_add (ip_punt_redirect_t * cfg,
		      u32 rx_sw_if_index,
		      ip_punt_redirect_rx_t * redirect,
		      fib_protocol_t fproto, vnet_link_t linkt)
{
  ip_punt_redirect_rx_t *new;

  if (~0 == rx_sw_if_index)
    {
      cfg->any_rx_sw_if_index = *redirect;
      new = &cfg->any_rx_sw_if_index;
    }
  else
    {
      vec_validate_init_empty (cfg->redirect_by_rx_sw_if_index,
			       rx_sw_if_index, uninit_rx_redirect);
      cfg->redirect_by_rx_sw_if_index[rx_sw_if_index] = *redirect;
      new = &cfg->redirect_by_rx_sw_if_index[rx_sw_if_index];
    }

  new->adj_index = adj_nbr_add_or_lock (fproto, linkt,
					&redirect->nh,
					redirect->tx_sw_if_index);
}

void
ip_punt_redirect_del (ip_punt_redirect_t * cfg, u32 rx_sw_if_index)
{
  ip_punt_redirect_rx_t *old;

  if (~0 == rx_sw_if_index)
    {
      old = &cfg->any_rx_sw_if_index;
    }
  else
    {
      old = &cfg->redirect_by_rx_sw_if_index[rx_sw_if_index];
    }

  if ((old == NULL) || (old->adj_index == ADJ_INDEX_INVALID))
    return;

  adj_unlock (old->adj_index);
  *old = uninit_rx_redirect;
}

void
ip4_punt_redirect_add (u32 rx_sw_if_index,
		       u32 tx_sw_if_index, ip46_address_t * nh)
{
  ip_punt_redirect_rx_t rx = {
    .tx_sw_if_index = tx_sw_if_index,
    .nh = *nh,
  };

  ip_punt_redirect_add (&ip4_punt_redirect_cfg,
			rx_sw_if_index, &rx, FIB_PROTOCOL_IP4, VNET_LINK_IP4);

  vnet_feature_enable_disable ("ip4-punt", "ip4-punt-redirect", 0, 1, 0, 0);
}

void
ip4_punt_redirect_del (u32 rx_sw_if_index)
{
  vnet_feature_enable_disable ("ip4-punt", "ip4-punt-redirect", 0, 0, 0, 0);

  ip_punt_redirect_del (&ip4_punt_redirect_cfg, rx_sw_if_index);
}

static clib_error_t *
ip4_punt_redirect_cmd (vlib_main_t * vm,
		       unformat_input_t * main_input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 rx_sw_if_index = 0;
  u32 tx_sw_if_index = 0;
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
			 unformat_ip4_address,
			 &nh.ip4,
			 unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
	;
      else if (unformat (line_input, "via %U",
			 unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
	clib_memset (&nh, 0, sizeof (nh));
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (is_add)
    {
      if (rx_sw_if_index && tx_sw_if_index)
	{
	  ip4_punt_redirect_add (rx_sw_if_index, tx_sw_if_index, &nh);
	}
    }
  else
    {
      if (rx_sw_if_index)
	{
	  ip4_punt_redirect_del (rx_sw_if_index);
	}
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

u8 *
format_ip_punt_redirect (u8 * s, va_list * args)
{
  ip_punt_redirect_t *cfg = va_arg (*args, ip_punt_redirect_t *);
  ip_punt_redirect_rx_t *rx;
  u32 rx_sw_if_index;
  vnet_main_t *vnm = vnet_get_main ();

  vec_foreach_index (rx_sw_if_index, cfg->redirect_by_rx_sw_if_index)
  {
    rx = &cfg->redirect_by_rx_sw_if_index[rx_sw_if_index];
    if (~0 != rx->tx_sw_if_index)
      {
	s = format (s, " rx %U redirect via %U %U\n",
		    format_vnet_sw_interface_name, vnm,
		    vnet_get_sw_interface (vnm, rx_sw_if_index),
		    format_ip46_address, &rx->nh, IP46_TYPE_ANY,
		    format_vnet_sw_interface_name, vnm,
		    vnet_get_sw_interface (vnm, rx->tx_sw_if_index));
      }
  }
  if (~0 != cfg->any_rx_sw_if_index.tx_sw_if_index)
    {
      s = format (s, " rx all redirect via %U %U\n",
		  format_ip46_address, &cfg->any_rx_sw_if_index.nh,
		  IP46_TYPE_ANY, format_vnet_sw_interface_name, vnm,
		  vnet_get_sw_interface (vnm,
					 cfg->
					 any_rx_sw_if_index.tx_sw_if_index));
    }

  return (s);
}

static clib_error_t *
ip4_punt_redirect_show_cmd (vlib_main_t * vm,
			    unformat_input_t * main_input,
			    vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "%U", format_ip_punt_redirect, &ip4_punt_redirect_cfg);

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

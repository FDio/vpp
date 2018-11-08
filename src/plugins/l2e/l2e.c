/*
 * l2_emulation.h : Extract L3 packets from the L2 input and feed
 *                   them into the L3 path.
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <plugins/l2e/l2e.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

/**
 * Grouping of global data for the L2 emulation feature
 */
typedef struct l2_emulation_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 l2_input_feat_next[32];
} l2_emulation_main_t;

static l2_emulation_main_t l2_emulation_main;

/**
 * Per-interface L2 configuration
 */
typedef struct l2_emulation_t_
{
  /**
   * Enabled or Disabled.
   *  this is required since one L3 protocl can be enabled, but others not
   */
  u8 enabled;
} l2_emulation_t;

/**
 * A zero'd out struct we can use in the vec_validate
 */
static const l2_emulation_t ezero = { };

/**
 * Per-interface vector of emulation configs
 */
l2_emulation_t *l2_emulations;

void
l2_emulation_enable (u32 sw_if_index)
{
  vec_validate_init_empty (l2_emulations, sw_if_index, ezero);

  l2_emulation_t *l23e = &l2_emulations[sw_if_index];

  l23e->enabled = 1;

  /*
   * L3 enable the interface - using IP unnumbered from the control
   * plane may not be possible since there may be no BVI interface
   * to which to unnumber
   */
  ip4_sw_interface_enable_disable (sw_if_index, 1);
  ip6_sw_interface_enable_disable (sw_if_index, 1);

  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_L2_EMULATION, 1);
}


void
l2_emulation_disable (u32 sw_if_index)
{
  if (vec_len (l2_emulations) >= sw_if_index)
    {
      l2_emulation_t *l23e = &l2_emulations[sw_if_index];
      clib_memset (l23e, 0, sizeof (*l23e));

      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_L2_EMULATION, 0);
      ip4_sw_interface_enable_disable (sw_if_index, 0);
      ip6_sw_interface_enable_disable (sw_if_index, 0);
    }
}

static clib_error_t *
l2_emulation_interface_add_del (vnet_main_t * vnm,
				u32 sw_if_index, u32 is_add)
{
  if (is_add)
    {
      vec_validate_init_empty (l2_emulations, sw_if_index, ezero);
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (l2_emulation_interface_add_del);

static clib_error_t *
l2_emulation_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");

  if (enable)
    l2_emulation_enable (sw_if_index);
  else
    l2_emulation_disable (sw_if_index);

  return (NULL);
}

/*?
 * Configure l2 emulation.
 *  When the interface is in L2 mode, configure the extraction of L3
 *  packets out of the L2 path and into the L3 path.
 *
 * @cliexpar
 * @cliexstart{set interface l2 input l2-emulation <interface-name> [disable]}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_emulation_cli_node, static) = {
  .path = "set interface l2 l2-emulation",
  .short_help =
  "set interface l2 l2-emulation <interface-name> [disable|enable]\n",
  .function = l2_emulation_cli,
};
/* *INDENT-ON* */

static clib_error_t *
l2_emulation_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  l2_emulation_t *l23e;
  u32 sw_if_index;

  vec_foreach_index (sw_if_index, l2_emulations)
  {
    l23e = &l2_emulations[sw_if_index];
    if (l23e->enabled)
      {
	vlib_cli_output (vm, "%U\n",
			 format_vnet_sw_if_index_name, vnm, sw_if_index);
      }
  }
  return (NULL);
}

/*?
 * Show l2 emulation.
 *  When the interface is in L2 mode, configure the extraction of L3
 *  packets out of the L2 path and into the L3 path.
 *
 * @cliexpar
 * @cliexstart{show interface l2 l2-emulation}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_emulation_show_node, static) = {
  .path = "show interface l2 l2-emulation",
  .short_help = "show interface l2 l2-emulation\n",
  .function = l2_emulation_show,
};
/* *INDENT-ON* */

#define foreach_l2_emulation                    \
  _(IP4, "Extract IPv4")                        \
  _(IP6, "Extract IPv6")

typedef enum
{
#define _(sym,str) L2_EMULATION_ERROR_##sym,
  foreach_l2_emulation
#undef _
    L2_EMULATION_N_ERROR,
} l2_emulation_error_t;

static char *l2_emulation_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_emulation
#undef _
};

typedef enum
{
#define _(sym,str) L2_EMULATION_NEXT_##sym,
  foreach_l2_emulation
#undef _
    L2_EMULATION_N_NEXT,
} l2_emulation_next_t;

/**
 * per-packet trace data
 */
typedef struct l2_emulation_trace_t_
{
  /* per-pkt trace data */
  u8 extracted;
} l2_emulation_trace_t;

static uword
l2_emulation_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  l2_emulation_main_t *em = &l2_emulation_main;
  u32 n_left_from, *from, *to_next;
  l2_emulation_next_t next_index;
  u32 ip4_hits = 0;
  u32 ip6_hits = 0;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  u32 sw_if_index0, sw_if_index1;
	  u16 ether_type0, ether_type1;
	  u32 next0 = ~0, next1 = ~0;
	  u8 l2_len0, l2_len1;
	  u32 bi0, bi1;
	  u8 *h0, *h1;

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  l2_len0 = vnet_buffer (b0)->l2.l2_len;
	  l2_len1 = vnet_buffer (b1)->l2.l2_len;

	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);

	  ether_type0 = clib_net_to_host_u16 (*(u16 *) (h0 + l2_len0 - 2));
	  ether_type1 = clib_net_to_host_u16 (*(u16 *) (h1 + l2_len1 - 2));
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  /*
	   * only extract unicast
	   */
	  if (PREDICT_TRUE (!(h0[0] & 0x1)))
	    {
	      switch (ether_type0)
		{
		case ETHERNET_TYPE_IP4:
		  ASSERT (l2_emulations[sw_if_index0].enabled);
		  ++ip4_hits;
		  next0 = L2_EMULATION_NEXT_IP4;
		  vlib_buffer_advance (b0, l2_len0);
		  break;
		case ETHERNET_TYPE_IP6:
		  ASSERT (l2_emulations[sw_if_index0].enabled);
		  ++ip6_hits;
		  next0 = L2_EMULATION_NEXT_IP6;
		  vlib_buffer_advance (b0, l2_len0);
		default:
		  break;
		}
	    }
	  if (PREDICT_TRUE (!(h1[0] & 0x1)))
	    {
	      switch (ether_type1)
		{
		case ETHERNET_TYPE_IP4:
		  ASSERT (l2_emulations[sw_if_index1].enabled);
		  ++ip4_hits;
		  next1 = L2_EMULATION_NEXT_IP4;
		  vlib_buffer_advance (b1, l2_len1);
		  break;
		case ETHERNET_TYPE_IP6:
		  ASSERT (l2_emulations[sw_if_index1].enabled);
		  ++ip6_hits;
		  next1 = L2_EMULATION_NEXT_IP6;
		  vlib_buffer_advance (b1, l2_len1);
		default:
		  break;
		}
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_emulation_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->extracted = (next0 != ~0);
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_emulation_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->extracted = (next1 != ~0);
	    }

	  /* Determine the next node and remove ourself from bitmap */
	  if (PREDICT_TRUE (next0 == ~0))
	    next0 = vnet_l2_feature_next (b0, em->l2_input_feat_next,
					  L2INPUT_FEAT_L2_EMULATION);

	  /* Determine the next node and remove ourself from bitmap */
	  if (PREDICT_TRUE (next1 == ~0))
	    next1 = vnet_l2_feature_next (b1, em->l2_input_feat_next,
					  L2INPUT_FEAT_L2_EMULATION);

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 sw_if_index0;
	  u16 ether_type0;
	  u32 next0 = ~0;
	  u8 l2_len0;
	  u32 bi0;
	  u8 *h0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  l2_len0 = vnet_buffer (b0)->l2.l2_len;

	  h0 = vlib_buffer_get_current (b0);
	  ether_type0 = clib_net_to_host_u16 (*(u16 *) (h0 + l2_len0 - 2));
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /*
	   * only extract unicast
	   */
	  if (PREDICT_TRUE (!(h0[0] & 0x1)))
	    {
	      switch (ether_type0)
		{
		case ETHERNET_TYPE_IP4:
		  ASSERT (l2_emulations[sw_if_index0].enabled);
		  ++ip4_hits;
		  next0 = L2_EMULATION_NEXT_IP4;
		  vlib_buffer_advance (b0, l2_len0);
		  break;
		case ETHERNET_TYPE_IP6:
		  ASSERT (l2_emulations[sw_if_index0].enabled);
		  ++ip6_hits;
		  next0 = L2_EMULATION_NEXT_IP6;
		  vlib_buffer_advance (b0, l2_len0);
		default:
		  break;
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_emulation_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->extracted = (next0 != ~0);
	    }

	  /* Determine the next node and remove ourself from bitmap */
	  if (PREDICT_TRUE (next0 == ~0))
	    next0 = vnet_l2_feature_next (b0, em->l2_input_feat_next,
					  L2INPUT_FEAT_L2_EMULATION);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       L2_EMULATION_ERROR_IP4, ip4_hits);
  vlib_node_increment_counter (vm, node->node_index,
			       L2_EMULATION_ERROR_IP6, ip6_hits);

  return frame->n_vectors;
}

/* packet trace format function */
static u8 *
format_l2_emulation_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_emulation_trace_t *t = va_arg (*args, l2_emulation_trace_t *);

  s = format (s, "l2-emulation: %s", (t->extracted ? "yes" : "no"));

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_emulation_node) = {
  .function = l2_emulation_node_fn,
  .name = "l2-emulation",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_emulation_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_emulation_error_strings),
  .error_strings = l2_emulation_error_strings,

  .n_next_nodes = L2_EMULATION_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [L2_EMULATION_NEXT_IP4] = "ip4-input",
    [L2_EMULATION_NEXT_IP6] = "ip6-input",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2_emulation_node, l2_emulation_node_fn);


static clib_error_t *
l2_emulation_init (vlib_main_t * vm)
{
  l2_emulation_main_t *em = &l2_emulation_main;

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2_emulation_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next);

  return 0;
}

VLIB_INIT_FUNCTION (l2_emulation_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

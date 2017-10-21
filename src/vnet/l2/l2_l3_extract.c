/*
 * l2_l3_extract.h : Extract L3 packets from the L2 input and feed
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

#include <vnet/l2/l2_l3_extract.h>

/**
 * Grouping of global data for the Extract feature
 */
typedef struct l2_l3_extract_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 l2_input_feat_next[32];
} l2_l3_extract_main_t;

static l2_l3_extract_main_t l2_l3_extract_main;

/**
 * Per-interface L2 configuration
 */
typedef struct l2_l3_extract_t_
{
  /**
   * Enabled or Disabled.
   *  this is required since one L3 protocl can be enabled, but others not
   */
  u8 enabled;

  /**
   * Include L2 multicast packets for extraction
   */
  u8 include_multicast;

  /**
   * Include L2 braodcast packets for extraction
   */
  u8 include_broadcast;
} l2_l3_extract_t;

/**
 * A zero'd out struct we can use in the vec_validate
 */
static const l2_l3_extract_t ezero = { };

/**
 * Per-interface vector, per-l3-proto of extraction configs
 */
l2_l3_extract_t *l2_l3_extracts[FIB_PROTOCOL_MAX];

/**
 * Configure l3 extraction
 */
void
l2_l3_extract_enable (fib_protocol_t l3_proto,
		      u32 sw_if_index,
		      u8 include_multicast, u8 include_broadcast)
{
  vec_validate_init_empty (l2_l3_extracts[l3_proto], sw_if_index, ezero);

  l2_l3_extract_t *l23e = &l2_l3_extracts[l3_proto][sw_if_index];

  l23e->enabled = 1;
  l23e->include_multicast = include_multicast;
  l23e->include_broadcast = include_broadcast;

  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_L3_EXTRACT, 1);
}


void
l2_l3_extract_disable (fib_protocol_t l3_proto,
		       u32 sw_if_index,
		       u8 include_multicast, u8 include_broadcast)
{
  if (vec_len (l2_l3_extracts[l3_proto]) >= sw_if_index)
    {
      l2_l3_extract_t *l23e = &l2_l3_extracts[l3_proto][sw_if_index];
      memset (l23e, 0, sizeof (*l23e));

      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_L3_EXTRACT, 0);
    }
}

static clib_error_t *
l2_l3_extract_cli (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u8 enable = 1, mcast = 0, bcast = 0;
  fib_protocol_t proto = FIB_PROTOCOL_IP4;
  u32 sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "mulitcast"))
	mcast = 1;
      else if (unformat (input, "broadcast"))
	bcast = 1;
      else if (unformat (input, "ip4"))
	proto = FIB_PROTOCOL_IP4;
      else if (unformat (input, "ip6"))
	proto = FIB_PROTOCOL_IP6;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");

  if (enable)
    l2_l3_extract_enable (proto, sw_if_index, mcast, bcast);
  else
    l2_l3_extract_disable (proto, sw_if_index, mcast, bcast);

  return (NULL);
}

/*?
 * Configure l2 l3 extraction.
 *  When the interface is in L2 mode, configure the extraction of L3
 *  packets out of the L2 path and into the L3 path.
 *
 * @cliexpar
 * @cliexstart{set interface l2 input l3-extract <interface-name> <ip4|ip6> [multicast] [broadcast] [disable]
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_l3_extract_cli_node, static) = {
  .path = "set interface l2 l3-extract",
  .short_help =
  "set interface l2 input l3-extract <interface-name> <ip4|ip6> [multicast] [broadcast] [disable|enable]\n",
  .function = l2_l3_extract_cli,
};
/* *INDENT-ON* */

static clib_error_t *
l2_l3_extract_show (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  fib_protocol_t l3_proto;
  l2_l3_extract_t *l23e;
  u32 sw_if_index;

  FOR_EACH_FIB_PROTOCOL (l3_proto)
  {
    vec_foreach_index (sw_if_index, l2_l3_extracts[l3_proto])
    {
      l23e = &l2_l3_extracts[l3_proto][sw_if_index];
      if (l23e->enabled)
	{
	  vlib_cli_output (vm, "%U %U %s %s\n",
			   format_vnet_sw_if_index_name, vnm, sw_if_index,
			   format_fib_protocol, l3_proto,
			   (l23e->include_multicast ? "multicast" : ""),
			   (l23e->include_broadcast ? "broadcast" : ""));
	}
    }
  }
  return (NULL);
}

/*?
 * Configure l2 l3 extraction.
 *  When the interface is in L2 mode, configure the extraction of L3
 *  packets out of the L2 path and into the L3 path.
 *
 * @cliexpar
 * @cliexstart{set interface l2 input l3-extract <interface-name> <ip4|ip6> [multicast] [broadcast] [disable]
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_l3_extract_show_node, static) = {
  .path = "show interface l2 l3-extract",
  .short_help = "show interface l2 l3-extract\n",
  .function = l2_l3_extract_show,
};
/* *INDENT-ON* */

#define foreach_l2_l3_extract             \
  _(IP4, "Extract IPv4")                 \
  _(IP6, "Extract IPv6")

typedef enum
{
#define _(sym,str) L2_L3_EXTRACT_ERROR_##sym,
  foreach_l2_l3_extract
#undef _
    L2_L3_EXTRACT_N_ERROR,
} l2_l3_extract_error_t;

static char *l2_l3_extract_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_l3_extract
#undef _
};

typedef enum
{
#define _(sym,str) L2_L3_EXTRACT_NEXT_##sym,
  foreach_l2_l3_extract
#undef _
    L2_L3_EXTRACT_N_NEXT,
} l2_l3_extract_next_t;

/**
 * per-packet trace data
 */
typedef struct l2_l3_extract_trace_t_
{
  /* per-pkt trace data */
  u8 extracted;
} l2_l3_extract_trace_t;

static uword
l2_l3_extract_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  l2_l3_extract_main_t *em = &l2_l3_extract_main;
  u32 n_left_from, *from, *to_next;
  l2_l3_extract_next_t next_index;
  u32 ip4_hits = 0;
  u32 ip6_hits = 0;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  l2_l3_extract_t *l23e0;
	  ethernet_header_t *h0;
	  vlib_buffer_t *b0;
	  u32 sw_if_index0;
	  u16 ether_type0;
	  u32 next0 = ~0;
	  u32 bi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);
	  ether_type0 = clib_net_to_host_u16 (h0->type);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  switch (ether_type0)
	    {
	    case ETHERNET_TYPE_IP4:
	      if (vec_len (l2_l3_extracts[FIB_PROTOCOL_IP4]) >= sw_if_index0)
		{
		  l23e0 = &l2_l3_extracts[FIB_PROTOCOL_IP4][sw_if_index0];
		  if (l23e0->enabled)
		    {
		      ++ip4_hits;
		      next0 = L2_L3_EXTRACT_NEXT_IP4;
		      vlib_buffer_advance (b0,
					   ethernet_buffer_header_size (b0));
		    }
		}
	      break;
	    case ETHERNET_TYPE_IP6:
	      if (vec_len (l2_l3_extracts[FIB_PROTOCOL_IP6]) >= sw_if_index0)
		{
		  l23e0 = &l2_l3_extracts[FIB_PROTOCOL_IP6][sw_if_index0];
		  if (l23e0->enabled)
		    {
		      ++ip6_hits;
		      next0 = L2_L3_EXTRACT_NEXT_IP6;
		      vlib_buffer_advance (b0,
					   ethernet_buffer_header_size (b0));
		    }
		}
	    default:
	      break;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_l3_extract_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->extracted = (next0 != ~0);
	    }

	  /* Determine the next node and remove ourself from bitmap */
	  if (PREDICT_TRUE (next0 == ~0))
	    next0 = vnet_l2_feature_next (b0, em->l2_input_feat_next,
					  L2INPUT_FEAT_L3_EXTRACT);
	  else
	    vnet_buffer (b0)->l2.feature_bitmap &= ~L2INPUT_FEAT_L3_EXTRACT;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       L2_L3_EXTRACT_ERROR_IP4, ip4_hits);
  vlib_node_increment_counter (vm, node->node_index,
			       L2_L3_EXTRACT_ERROR_IP6, ip6_hits);

  return frame->n_vectors;
}

/* packet trace format function */
static u8 *
format_l2_l3_extract_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_l3_extract_trace_t *t = va_arg (*args, l2_l3_extract_trace_t *);

  s = format (s, "l2-l3-extract: %s", (t->extracted ? "yes" : "no"));

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_l3_extract_node) = {
  .function = l2_l3_extract_node_fn,
  .name = "l2-l3-extract",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_l3_extract_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_l3_extract_error_strings),
  .error_strings = l2_l3_extract_error_strings,

  .n_next_nodes = L2_L3_EXTRACT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [L2_L3_EXTRACT_NEXT_IP4] = "ip4-input",
    [L2_L3_EXTRACT_NEXT_IP6] = "ip6-input",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2_l3_extract_node, l2_l3_extract_node_fn);


static clib_error_t *
l2_l3_extract_init (vlib_main_t * vm)
{
  l2_l3_extract_main_t *em = &l2_l3_extract_main;

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2_l3_extract_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next);

  return 0;
}

VLIB_INIT_FUNCTION (l2_l3_extract_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

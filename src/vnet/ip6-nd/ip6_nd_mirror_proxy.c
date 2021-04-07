/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip-neighbor/ip6_neighbor.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip-neighbor/ip_neighbor_dp.h>
#include <vnet/ip6-nd/ip6_nd_inline.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_ll_table.h>

#include <vppinfra/error.h>

int
ip6_nd_proxy_enable_disable (u32 sw_if_index, u8 enable)
{

  if (enable)
    {
      vnet_feature_enable_disable ("ip6-unicast", "ip6-unicast-nd-proxy",
				   sw_if_index, 1, NULL, 0);
      vnet_feature_enable_disable ("ip6-multicast", "ip6-multicast-nd-proxy",
				   sw_if_index, 1, NULL, 0);
    }
  else
    {
      vnet_feature_enable_disable ("ip6-unicast", "ip6-unicast-nd-proxy",
				   sw_if_index, 0, NULL, 0);
      vnet_feature_enable_disable ("ip6-multicast", "ip6-multicast-nd-proxy",
				   sw_if_index, 0, NULL, 0);
    }
  return 0;
}

static clib_error_t *
set_int_ip6_nd_proxy_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;
  int enable = 0;

  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "unknown input '%U'", format_unformat_error,
			      input);

  ip6_nd_proxy_enable_disable (sw_if_index, enable);

  return 0;
}

VLIB_CLI_COMMAND (set_int_ip6_nd_proxy_enable_command, static) = {
  .path = "set interface ip6-nd proxy",
  .short_help = "set interface ip6-nd proxy <intfc> [enable|disable]",
  .function = set_int_ip6_nd_proxy_command_fn,
};

typedef struct
{
  u8 is_multicast;
  u32 sw_if_index;
} vnet_ip6_nd_proxy_trace_t;

static u8 *
format_ip6_nd_proxy_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_ip6_nd_proxy_trace_t *t = va_arg (*args, vnet_ip6_nd_proxy_trace_t *);
  u32 indent = format_get_indent (s);

  if (t->is_multicast)
    s = format (s, "%U %U multicast ", format_white_space, indent,
		format_vnet_sw_if_index_name, vnm, t->sw_if_index);
  else
    s = format (s, "%U %U unicast ", format_white_space, indent,
		format_vnet_sw_if_index_name, vnm, t->sw_if_index);

  return s;
}

static_always_inline void
ip6_nd_proxy_unicast (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_buffer_t *b0, ip6_header_t *ip6, u32 *next0)
{
  if (PREDICT_FALSE (ip6->protocol == IP_PROTOCOL_ICMP6))
    {
      icmp46_header_t *icmp0;
      icmp6_type_t type0;

      icmp0 = ip6_next_header (ip6);
      type0 = icmp0->type;
      if (type0 == ICMP6_neighbor_solicitation ||
	  type0 == ICMP6_neighbor_advertisement)
	{
	  icmp6_neighbor_solicitation_or_advertisement_header_t *icmp6_nsa;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
	    *icmp6_nd_ell_addr;
	  u32 sw_if_index0;

	  icmp6_nsa = (void *) icmp0;
	  icmp6_nd_ell_addr = (void *) (icmp6_nsa + 1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* unicast neighbor solicitation */
	  fib_node_index_t fei;
	  u32 fib_index;

	  fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index0);

	  if (~0 == fib_index)
	    {
	      *next0 = ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP;
	    }
	  else
	    {
	      if (ip6_address_is_link_local_unicast (&ip6->dst_address))
		{
		  fei = ip6_fib_table_lookup_exact_match (
		    ip6_ll_fib_get (sw_if_index0), &ip6->dst_address, 128);
		}
	      else
		{
		  fei = ip6_fib_table_lookup_exact_match (
		    fib_index, &ip6->dst_address, 128);
		}

	      if (FIB_NODE_INDEX_INVALID != fei)
		{
		  *next0 = ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY;
		  icmp6_send_neighbor_advertisement (
		    vm, b0, ip6, icmp6_nsa, icmp6_nd_ell_addr, sw_if_index0);
		}
	    }
	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vnet_ip6_nd_proxy_trace_t *t;
	      t = vlib_add_trace (vm, node, b0, sizeof (t[0]));
	      t->sw_if_index = sw_if_index0;
	      t->is_multicast = 0;
	    }
	}
    }
}

static_always_inline void
ip6_nd_proxy_multicast (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_buffer_t *b0, ip6_header_t *ip6, u32 *next0)
{
  if (PREDICT_FALSE (ip6->protocol == IP_PROTOCOL_ICMP6))
    {
      icmp46_header_t *icmp0;
      icmp6_type_t type0;

      icmp0 = ip6_next_header (ip6);
      type0 = icmp0->type;
      if (type0 == ICMP6_neighbor_solicitation ||
	  type0 == ICMP6_neighbor_advertisement)
	{
	  icmp6_neighbor_solicitation_or_advertisement_header_t *icmp6_nsa;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
	    *icmp6_nd_ell_addr;
	  u32 sw_if_index0;

	  icmp6_nsa = (void *) icmp0;
	  icmp6_nd_ell_addr = (void *) (icmp6_nsa + 1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  if (type0 == ICMP6_neighbor_solicitation)
	    {
	      if (
		(icmp6_nd_ell_addr->header.type ==
		 ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address) &&
		(!ip6_address_is_unspecified (&ip6->src_address)) &&
		(!ip6_address_is_link_local_unicast (&ip6->src_address)))
		{
		  ip_neighbor_learn_t learn = { .sw_if_index = sw_if_index0,
						.ip = {
						  .version = AF_IP6,
						  .ip.ip6 = ip6->src_address,
						} };
		  clib_memcpy (&learn.mac, icmp6_nd_ell_addr->ethernet_address,
			       sizeof (learn.mac));
		  ip_neighbor_learn_dp (&learn);

		  *next0 = ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY;
		  icmp6_send_neighbor_advertisement (
		    vm, b0, ip6, icmp6_nsa, icmp6_nd_ell_addr, sw_if_index0);
		}
	    }
	  else // type0 = ICMP6_neighbor_advertisement
	    {
	      icmp6_neighbor_solicitation_or_advertisement_header_t
		*icmp6_nsa = (void *) icmp0;
	      icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
		*icmp6_nd_ell_addr = (void *) (icmp6_nsa + 1);
	      if (
		(icmp6_nd_ell_addr->header.type ==
		 ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address) &&
		(!ip6_address_is_unspecified (&ip6->src_address)) &&
		(!ip6_address_is_link_local_unicast (&ip6->src_address)))
		{
		  ip_neighbor_learn_t learn = { .sw_if_index = sw_if_index0,
						.ip = {
						  .version = AF_IP6,
						  .ip.ip6 =
						    icmp6_nsa->target_address,
						} };
		  clib_memcpy (&learn.mac, icmp6_nd_ell_addr->ethernet_address,
			       sizeof (learn.mac));
		  ip_neighbor_learn_dp (&learn);

		  *next0 = ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP;
		}
	    }

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vnet_ip6_nd_proxy_trace_t *t;
	      t = vlib_add_trace (vm, node, b0, sizeof (t[0]));
	      t->sw_if_index = sw_if_index0;
	      t->is_multicast = 1;
	    }
	}
    }
}

static_always_inline uword
ip6_nd_proxy_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, u8 is_multicast)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index, n_left_to_next;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  vlib_get_buffers (vm, from, bufs, n_left_from);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 4 && n_left_to_next > 2)
	{
	  ip6_header_t *ip6_0, *ip6_1;
	  u32 next0, next1;
	  u32 bi0, bi1;

	  /* Prefetch next iteration. */
	  {
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    vlib_prefetch_buffer_header (b[3], LOAD);

	    vlib_prefetch_buffer_data (b[2], LOAD);
	    vlib_prefetch_buffer_data (b[3], LOAD);
	  }

	  /*
	   * speculatively enqueue b0 and b1 to the current next frame
	   */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next += 2;
	  n_left_to_next -= 2;

	  vnet_feature_next (&next0, b[0]);
	  vnet_feature_next (&next1, b[1]);

	  ip6_0 = vlib_buffer_get_current (b[0]);
	  ip6_1 = vlib_buffer_get_current (b[1]);

	  if (is_multicast)
	    {
	      ip6_nd_proxy_multicast (vm, node, b[0], ip6_0, &next0);
	      ip6_nd_proxy_multicast (vm, node, b[1], ip6_1, &next1);
	    }
	  else
	    {
	      ip6_nd_proxy_unicast (vm, node, b[0], ip6_0, &next0);
	      ip6_nd_proxy_unicast (vm, node, b[1], ip6_1, &next1);
	    }
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);

	  b += 2;
	  from += 2;
	  n_left_from -= 2;
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip6_header_t *ip6_0;
	  u32 next0, bi0;

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next += 1;
	  n_left_to_next -= 1;

	  vnet_feature_next (&next0, b[0]);
	  ip6_0 = vlib_buffer_get_current (b[0]);

	  if (is_multicast)
	    ip6_nd_proxy_multicast (vm, node, b[0], ip6_0, &next0);
	  else
	    ip6_nd_proxy_unicast (vm, node, b[0], ip6_0, &next0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	  b += 1;
	  from += 1;
	  n_left_from -= 1;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (ip6_unicast_nd_proxy_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip6_nd_proxy_node_inline (vm, node, frame, 0 /* is_multicast */);
}

VLIB_REGISTER_NODE (ip6_unicast_nd_proxy_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_nd_proxy_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = ICMP6_NEIGHBOR_SOLICITATION_N_NEXT,
  .next_nodes = {
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP] = "ip6-drop",
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY] = "interface-output",
  },
  .name = "ip6-unicast-nd-proxy",
};

VLIB_NODE_FN (ip6_multicast_nd_proxy_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip6_nd_proxy_node_inline (vm, node, frame, 1 /* is_multicast */);
}

VLIB_REGISTER_NODE (ip6_multicast_nd_proxy_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_nd_proxy_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = ICMP6_NEIGHBOR_SOLICITATION_N_NEXT,
  .next_nodes = {
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP] = "ip6-drop",
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY] = "interface-output",
  },
  .name = "ip6-multicast-nd-proxy",
};

VNET_FEATURE_INIT (ip6_unicast_nd_proxy_node, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-unicast-nd-proxy",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

VNET_FEATURE_INIT (ip6_multicast_nd_proxy_node, static) = {
  .arc_name = "ip6-multicast",
  .node_name = "ip6-multicast-nd-proxy",
  .runs_before = VNET_FEATURES ("ip6-mfib-forward-lookup"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

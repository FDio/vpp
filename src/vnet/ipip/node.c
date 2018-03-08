/*
 * node.c: ipip packet processing
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or aipiped to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/ipip/ipip.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/mpls/mpls.h>
#include <vnet/pg/pg.h>
#include <vppinfra/sparse_vec.h>

#define foreach_ipip_input_next                                                \
  _(PUNT, "error-punt")                                                        \
  _(DROP, "error-drop")                                                        \
  _(IP4_INPUT, "ip4-input")                                                    \
  _(IP6_INPUT, "ip6-input")

typedef enum
{
#define _(s, n) IPIP_INPUT_NEXT_##s,
  foreach_ipip_input_next
#undef _
    IPIP_INPUT_N_NEXT,
} ipip_input_next_t;

typedef struct
{
  u32 tunnel_id;
  u32 length;
  ip46_address_t src;
  ip46_address_t dst;
  u8 is_ipv6;
} ipip_rx_trace_t;

u8 *
format_ipip_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipip_rx_trace_t *t = va_arg (*args, ipip_rx_trace_t *);

  s = format (s, "IPIP: tunnel %d len %d src %U dst %U", t->tunnel_id,
	      clib_net_to_host_u16 (t->length), format_ip46_address, &t->src,
	      IP46_TYPE_ANY, format_ip46_address, &t->dst, IP46_TYPE_ANY);
  return s;
}

always_inline uword
ipip_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * from_frame, bool is_ipv6)
{
  ipip_main_t *gm = &ipip_main;
  u32 n_left_from, next_index, *from, *to_next, n_left_to_next;
  u32 tunnel_sw_if_index = ~0;
  u32 thread_index = vlib_get_thread_index ();
  u32 len;
  vnet_interface_main_t *im = &gm->vnet_main->interface_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u32 next0 = IPIP_INPUT_NEXT_DROP;
	  ip46_address_t src0 = ip46_address_initializer, dst0 =
	    ip46_address_initializer;
	  ipip_transport_t transport0;
	  u8 inner_protocol0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (is_ipv6)
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      vlib_buffer_advance (b0, sizeof (*ip60));
	      ip_set (&src0, &ip60->src_address, false);
	      ip_set (&dst0, &ip60->dst_address, false);
	      inner_protocol0 = ip60->protocol;
	      transport0 = IPIP_TRANSPORT_IP6;
	    }
	  else
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      vlib_buffer_advance (b0, sizeof (*ip40));
	      ip_set (&src0, &ip40->src_address, true);
	      ip_set (&dst0, &ip40->dst_address, true);
	      inner_protocol0 = ip40->protocol;
	      transport0 = IPIP_TRANSPORT_IP4;
	    }

	  /*
	   * Find tunnel. First a lookup for P2P tunnels, then a lookup
	   * for multipoint tunnels
	   */
	  ipip_tunnel_key_t key0 = {.transport = transport0,
	    .fib_index = vnet_buffer (b0)->ip.fib_index,
	    .src = dst0,
	    .dst = src0
	  };
	  ipip_tunnel_t *t0 = ipip_tunnel_db_find (&key0);
	  if (!t0)
	    {
	      ip46_address_reset (&key0.dst);
	      t0 = ipip_tunnel_db_find (&key0);
	      if (!t0)
		{
		  next0 = IPIP_INPUT_NEXT_DROP;
		  b0->error = node->errors[IPIP_ERROR_NO_TUNNEL];
		  goto drop;
		}
	    }
	  tunnel_sw_if_index = t0->sw_if_index;

	  len = vlib_buffer_length_in_chain (vm, b0);
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;

	  if (inner_protocol0 == IP_PROTOCOL_IPV6)
	    next0 = IPIP_INPUT_NEXT_IP6_INPUT;
	  else if (inner_protocol0 == IP_PROTOCOL_IP_IN_IP)
	    next0 = IPIP_INPUT_NEXT_IP4_INPUT;

	  if (!is_ipv6 && t0->mode == IPIP_MODE_6RD
	      && t0->sixrd.security_check)
	    {
	      ip6_header_t *inner_ip60 = vlib_buffer_get_current (b0);
	      if (sixrd_get_addr_net (t0, inner_ip60->src_address.as_u64[0])
		  != ip40->src_address.as_u32)
		{
		  next0 = IPIP_INPUT_NEXT_DROP;
		  b0->error = node->errors[IPIP_ERROR_NO_TUNNEL];
		  goto drop;
		}
	    }

	  vlib_increment_combined_counter (im->combined_sw_if_counters +
					   VNET_INTERFACE_COUNTER_RX,
					   thread_index, tunnel_sw_if_index,
					   1 /* packets */ ,
					   len /* bytes */ );

	drop:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipip_rx_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->tunnel_id = tunnel_sw_if_index;
	      if (is_ipv6)
		{
		  tr->length = ip60->payload_length;
		  tr->src.ip6.as_u64[0] = ip60->src_address.as_u64[0];
		  tr->src.ip6.as_u64[1] = ip60->src_address.as_u64[1];
		  tr->dst.ip6.as_u64[0] = ip60->dst_address.as_u64[0];
		  tr->dst.ip6.as_u64[1] = ip60->dst_address.as_u64[1];
		}
	      else
		{
		  tr->length = ip40->length;
		  tr->src.ip4.as_u32 = ip40->src_address.as_u32;
		  tr->dst.ip4.as_u32 = ip40->dst_address.as_u32;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm,
			       !is_ipv6 ? ipip4_input_node.index :
			       ipip6_input_node.index, IPIP_ERROR_DECAP_PKTS,
			       from_frame->n_vectors);
  return from_frame->n_vectors;
}

static uword
ipip4_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  return ipip_input (vm, node, from_frame, /* is_ip6 */ false);
}

static uword
ipip6_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  return ipip_input (vm, node, from_frame, /* is_ip6 */ true);
}

static char *ipip_error_strings[] = {
#define _(sym,string) string,
  foreach_ipip_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ipip4_input_node) = {
    .function = ipip4_input,
    .name = "ipip4-input",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = IPIP_N_ERROR,
    .error_strings = ipip_error_strings,
    .n_next_nodes = IPIP_INPUT_N_NEXT,
    .next_nodes =
        {
#define _(s, n) [IPIP_INPUT_NEXT_##s] = n,
            foreach_ipip_input_next
#undef _
        },
    .format_trace = format_ipip_rx_trace,
};

VLIB_REGISTER_NODE(ipip6_input_node) = {
    .function = ipip6_input,
    .name = "ipip6-input",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = IPIP_N_ERROR,
    .error_strings = ipip_error_strings,
    .n_next_nodes = IPIP_INPUT_N_NEXT,
    .next_nodes =
        {
#define _(s, n) [IPIP_INPUT_NEXT_##s] = n,
            foreach_ipip_input_next
#undef _
        },
    .format_trace = format_ipip_rx_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH(ipip4_input_node, ipip4_input)
VLIB_NODE_FUNCTION_MULTIARCH(ipip6_input_node, ipip6_input)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

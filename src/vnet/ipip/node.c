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
#include <vnet/tunnel/tunnel_dp.h>
#include <vppinfra/sparse_vec.h>

#define foreach_ipip_input_next                                               \
  _ (PUNT, "error-punt")                                                      \
  _ (DROP, "error-drop")                                                      \
  _ (IP4_INPUT, "ip4-input")                                                  \
  _ (IP6_INPUT, "ip6-input")                                                  \
  _ (MPLS_INPUT, "mpls-input")

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

static u8 *
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
  clib_thread_index_t thread_index = vm->thread_index;
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
	  u8 inner_protocol0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  ipip_tunnel_key_t key0 = {
	    .fib_index = vnet_buffer (b0)->ip.fib_index,
	    .mode = IPIP_MODE_P2P,
	  };

	  if (is_ipv6)
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      /* Check for outer fragmentation */
	      if (ip60->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
		{
		  next0 = IPIP_INPUT_NEXT_DROP;
		  b0->error = node->errors[IPIP_ERROR_FRAGMENTED_PACKET];
		  goto drop;
		}

	      vlib_buffer_advance (b0, sizeof (*ip60));
	      ip_set (&key0.dst, &ip60->src_address, false);
	      ip_set (&key0.src, &ip60->dst_address, false);
	      inner_protocol0 = ip60->protocol;
	      key0.transport = IPIP_TRANSPORT_IP6;
	    }
	  else
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      /* Check for outer fragmentation */
	      if (ip40->flags_and_fragment_offset &
		  clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS))
		{
		  next0 = IPIP_INPUT_NEXT_DROP;
		  b0->error = node->errors[IPIP_ERROR_FRAGMENTED_PACKET];
		  goto drop;
		}
	      vlib_buffer_advance (b0, sizeof (*ip40));
	      ip_set (&key0.dst, &ip40->src_address, true);
	      ip_set (&key0.src, &ip40->dst_address, true);
	      inner_protocol0 = ip40->protocol;
	      key0.transport = IPIP_TRANSPORT_IP4;
	    }

	  /*
	   * Find tunnel. First a lookup for P2P tunnels, then a lookup
	   * for multipoint tunnels
	   */
	  ipip_tunnel_t *t0 = ipip_tunnel_db_find (&key0);
	  if (!t0)
	    {
	      ip46_address_reset (&key0.dst);
	      key0.mode = IPIP_MODE_6RD;
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
	    {
	      next0 = IPIP_INPUT_NEXT_IP6_INPUT;

	      if (is_ipv6)
		tunnel_decap_fixup_6o6 (t0->flags, (ip60 + 1), ip60);
	      else
		tunnel_decap_fixup_6o4 (t0->flags,
					(ip6_header_t *) (ip40 + 1), ip40);
	    }
	  else if (inner_protocol0 == IP_PROTOCOL_IP_IN_IP)
	    {
	      next0 = IPIP_INPUT_NEXT_IP4_INPUT;

	      if (is_ipv6)
		tunnel_decap_fixup_4o6 (t0->flags,
					(ip4_header_t *) (ip60 + 1), ip60);
	      else
		tunnel_decap_fixup_4o4 (t0->flags, ip40 + 1, ip40);
	    }
	  else if (inner_protocol0 == IP_PROTOCOL_MPLS_IN_IP)
	    {
	      next0 = IPIP_INPUT_NEXT_MPLS_INPUT;

	      if (is_ipv6)
		tunnel_decap_fixup_mplso6 (
		  t0->flags, (mpls_unicast_header_t *) (ip60 + 1), ip60);
	      else
		tunnel_decap_fixup_mplso4 (
		  t0->flags, (mpls_unicast_header_t *) ip40 + 1, ip40);
	    }

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

VLIB_NODE_FN (ipip4_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ipip_input (vm, node, from_frame, /* is_ip6 */ false);
}

VLIB_NODE_FN (ipip6_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ipip_input (vm, node, from_frame, /* is_ip6 */ true);
}

static char *ipip_error_strings[] = {
#define _(sym,string) string,
  foreach_ipip_error
#undef _
};

VLIB_REGISTER_NODE(ipip4_input_node) = {
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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

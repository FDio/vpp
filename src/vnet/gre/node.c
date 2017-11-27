/*
 * node.c: gre packet processing
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vnet/gre/gre.h>
#include <vnet/mpls/mpls.h>
#include <vppinfra/sparse_vec.h>

#define foreach_gre_input_next			\
_(PUNT, "error-punt")                           \
_(DROP, "error-drop")                           \
_(ETHERNET_INPUT, "ethernet-input")             \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")			\
_(MPLS_INPUT, "mpls-input")

typedef enum
{
#define _(s,n) GRE_INPUT_NEXT_##s,
  foreach_gre_input_next
#undef _
    GRE_INPUT_N_NEXT,
} gre_input_next_t;

typedef struct
{
  u32 tunnel_id;
  u32 length;
  ip46_address_t src;
  ip46_address_t dst;
  u8 is_ipv6;
} gre_rx_trace_t;

u8 *
format_gre_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gre_rx_trace_t *t = va_arg (*args, gre_rx_trace_t *);

  s = format (s, "GRE: tunnel %d len %d src %U dst %U",
	      t->tunnel_id, clib_net_to_host_u16 (t->length),
	      format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY);
  return s;
}

typedef struct
{
  /* Sparse vector mapping gre protocol in network byte order
     to next index. */
  u16 *next_by_protocol;
} gre_input_runtime_t;

always_inline uword
gre_input (vlib_main_t * vm,
	   vlib_node_runtime_t * node, vlib_frame_t * from_frame, u8 is_ipv6)
{
  gre_main_t *gm = &gre_main;
  __attribute__ ((unused)) u32 n_left_from, next_index, *from, *to_next;
  u64 cached_tunnel_key4;
  u64 cached_tunnel_key6[4];
  u32 cached_tunnel_sw_if_index = 0, tunnel_sw_if_index = 0;

  u32 thread_index = vlib_get_thread_index ();
  u32 len;
  vnet_interface_main_t *im = &gm->vnet_main->interface_main;

  if (!is_ipv6)
    memset (&cached_tunnel_key4, 0xff, sizeof (cached_tunnel_key4));
  else
    memset (&cached_tunnel_key6, 0xff, sizeof (cached_tunnel_key6));

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  gre_header_t *h0, *h1;
	  u16 version0, version1;
	  int verr0, verr1;
	  u32 i0, i1, next0, next1, protocol0, protocol1;
	  ip4_header_t *ip4_0, *ip4_1;
	  ip6_header_t *ip6_0, *ip6_1;
	  u32 ip4_tun_src0, ip4_tun_dst0;
	  u32 ip4_tun_src1, ip4_tun_dst1;
	  u64 ip6_tun_src0[2], ip6_tun_dst0[2];
	  u64 ip6_tun_src1[2], ip6_tun_dst1[2];

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, sizeof (h0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (h1[0]), LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  if (!is_ipv6)
	    {
	      /* ip4_local hands us the ip header, not the gre header */
	      ip4_0 = vlib_buffer_get_current (b0);
	      ip4_1 = vlib_buffer_get_current (b1);
	      /* Save src + dst ip4 address, e.g. for mpls-o-gre */
	      ip4_tun_src0 = ip4_0->src_address.as_u32;
	      ip4_tun_dst0 = ip4_0->dst_address.as_u32;
	      ip4_tun_src1 = ip4_1->src_address.as_u32;
	      ip4_tun_dst1 = ip4_1->dst_address.as_u32;

	      vlib_buffer_advance (b0, sizeof (*ip4_0));
	      vlib_buffer_advance (b1, sizeof (*ip4_1));
	    }
	  else
	    {
	      /* ip6_local hands us the ip header, not the gre header */
	      ip6_0 = vlib_buffer_get_current (b0);
	      ip6_1 = vlib_buffer_get_current (b1);
	      /* Save src + dst ip6 address, e.g. for mpls-o-gre */
	      ip6_tun_src0[0] = ip6_0->src_address.as_u64[0];
	      ip6_tun_src0[1] = ip6_0->src_address.as_u64[1];
	      ip6_tun_dst0[0] = ip6_0->dst_address.as_u64[0];
	      ip6_tun_dst0[1] = ip6_0->dst_address.as_u64[1];
	      ip6_tun_src1[0] = ip6_1->src_address.as_u64[0];
	      ip6_tun_src1[1] = ip6_1->src_address.as_u64[1];
	      ip6_tun_dst1[0] = ip6_1->dst_address.as_u64[0];
	      ip6_tun_dst1[1] = ip6_1->dst_address.as_u64[1];

	      vlib_buffer_advance (b0, sizeof (*ip6_0));
	      vlib_buffer_advance (b1, sizeof (*ip6_1));
	    }

	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);

	  /* Index sparse array with network byte order. */
	  protocol0 = h0->protocol;
	  protocol1 = h1->protocol;
	  sparse_vec_index2 (gm->next_by_protocol, protocol0, protocol1,
			     &i0, &i1);
	  next0 = vec_elt (gm->next_by_protocol, i0);
	  next1 = vec_elt (gm->next_by_protocol, i1);

	  b0->error =
	    node->errors[i0 ==
			 SPARSE_VEC_INVALID_INDEX ? GRE_ERROR_UNKNOWN_PROTOCOL
			 : GRE_ERROR_NONE];
	  b1->error =
	    node->errors[i1 ==
			 SPARSE_VEC_INVALID_INDEX ? GRE_ERROR_UNKNOWN_PROTOCOL
			 : GRE_ERROR_NONE];

	  version0 = clib_net_to_host_u16 (h0->flags_and_version);
	  verr0 = version0 & GRE_VERSION_MASK;
	  version1 = clib_net_to_host_u16 (h1->flags_and_version);
	  verr1 = version1 & GRE_VERSION_MASK;

	  b0->error = verr0 ? node->errors[GRE_ERROR_UNSUPPORTED_VERSION]
	    : b0->error;
	  next0 = verr0 ? GRE_INPUT_NEXT_DROP : next0;
	  b1->error = verr1 ? node->errors[GRE_ERROR_UNSUPPORTED_VERSION]
	    : b1->error;
	  next1 = verr1 ? GRE_INPUT_NEXT_DROP : next1;


	  /* RPF check for ip4/ip6 input */
	  if (PREDICT_TRUE (next0 == GRE_INPUT_NEXT_IP4_INPUT
			    || next0 == GRE_INPUT_NEXT_IP6_INPUT
			    || next0 == GRE_INPUT_NEXT_ETHERNET_INPUT
			    || next0 == GRE_INPUT_NEXT_MPLS_INPUT))
	    {

	      u64 key4, key6[4];
	      if (!is_ipv6)
		{
		  key4 = ((u64) (ip4_tun_dst0) << 32) | (u64) (ip4_tun_src0);
		}
	      else
		{
		  key6[0] = ip6_tun_dst0[0];
		  key6[1] = ip6_tun_dst0[1];
		  key6[2] = ip6_tun_src0[0];
		  key6[3] = ip6_tun_src0[1];
		}

	      if ((!is_ipv6 && cached_tunnel_key4 != key4) ||
		  (is_ipv6 && cached_tunnel_key6[0] != key6[0] &&
		   cached_tunnel_key6[1] != key6[1] &&
		   cached_tunnel_key6[2] != key6[2] &&
		   cached_tunnel_key6[3] != key6[3]))
		{
		  vnet_hw_interface_t *hi;
		  gre_tunnel_t *t;
		  uword *p;

		  if (!is_ipv6)
		    p = hash_get (gm->tunnel_by_key4, key4);
		  else
		    p = hash_get_mem (gm->tunnel_by_key6, key6);
		  if (!p)
		    {
		      next0 = GRE_INPUT_NEXT_DROP;
		      b0->error = node->errors[GRE_ERROR_NO_SUCH_TUNNEL];
		      goto drop0;
		    }
		  t = pool_elt_at_index (gm->tunnels, p[0]);
		  hi = vnet_get_hw_interface (gm->vnet_main, t->hw_if_index);
		  tunnel_sw_if_index = hi->sw_if_index;

		  cached_tunnel_sw_if_index = tunnel_sw_if_index;
		}
	      else
		{
		  tunnel_sw_if_index = cached_tunnel_sw_if_index;
		}
	    }
	  else
	    {
	      next0 = GRE_INPUT_NEXT_DROP;
	      goto drop0;
	    }
	  len = vlib_buffer_length_in_chain (vm, b0);
	  vlib_increment_combined_counter (im->combined_sw_if_counters
					   + VNET_INTERFACE_COUNTER_RX,
					   thread_index,
					   tunnel_sw_if_index,
					   1 /* packets */ ,
					   len /* bytes */ );

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;

	drop0:
	  if (PREDICT_TRUE (next1 == GRE_INPUT_NEXT_IP4_INPUT
			    || next1 == GRE_INPUT_NEXT_IP6_INPUT
			    || next1 == GRE_INPUT_NEXT_ETHERNET_INPUT
			    || next1 == GRE_INPUT_NEXT_MPLS_INPUT))
	    {
	      u64 key4, key6[4];
	      if (!is_ipv6)
		{
		  key4 = ((u64) (ip4_tun_dst1) << 32) | (u64) (ip4_tun_src1);
		}
	      else
		{
		  key6[0] = ip6_tun_dst1[0];
		  key6[1] = ip6_tun_dst1[1];
		  key6[2] = ip6_tun_src1[0];
		  key6[3] = ip6_tun_src1[1];
		}

	      if ((!is_ipv6 && cached_tunnel_key4 != key4) ||
		  (is_ipv6 && cached_tunnel_key6[0] != key6[0] &&
		   cached_tunnel_key6[1] != key6[1] &&
		   cached_tunnel_key6[2] != key6[2] &&
		   cached_tunnel_key6[3] != key6[3]))
		{
		  vnet_hw_interface_t *hi;
		  gre_tunnel_t *t;
		  uword *p;

		  if (!is_ipv6)
		    p = hash_get (gm->tunnel_by_key4, key4);
		  else
		    p = hash_get_mem (gm->tunnel_by_key6, key6);

		  if (!p)
		    {
		      next1 = GRE_INPUT_NEXT_DROP;
		      b1->error = node->errors[GRE_ERROR_NO_SUCH_TUNNEL];
		      goto drop1;
		    }
		  t = pool_elt_at_index (gm->tunnels, p[0]);
		  hi = vnet_get_hw_interface (gm->vnet_main, t->hw_if_index);
		  tunnel_sw_if_index = hi->sw_if_index;

		  cached_tunnel_sw_if_index = tunnel_sw_if_index;
		}
	      else
		{
		  tunnel_sw_if_index = cached_tunnel_sw_if_index;
		}
	    }
	  else
	    {
	      next1 = GRE_INPUT_NEXT_DROP;
	      goto drop1;
	    }
	  len = vlib_buffer_length_in_chain (vm, b1);
	  vlib_increment_combined_counter (im->combined_sw_if_counters
					   + VNET_INTERFACE_COUNTER_RX,
					   thread_index,
					   tunnel_sw_if_index,
					   1 /* packets */ ,
					   len /* bytes */ );

	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;

	drop1:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gre_rx_trace_t *tr = vlib_add_trace (vm, node,
						   b0, sizeof (*tr));
	      tr->tunnel_id = tunnel_sw_if_index;
	      if (!is_ipv6)
		{
		  tr->length = ip4_0->length;
		  tr->src.ip4.as_u32 = ip4_0->src_address.as_u32;
		  tr->dst.ip4.as_u32 = ip4_0->dst_address.as_u32;
		}
	      else
		{
		  tr->length = ip6_0->payload_length;
		  tr->src.ip6.as_u64[0] = ip6_0->src_address.as_u64[0];
		  tr->src.ip6.as_u64[1] = ip6_0->src_address.as_u64[1];
		  tr->dst.ip6.as_u64[0] = ip6_0->dst_address.as_u64[0];
		  tr->dst.ip6.as_u64[1] = ip6_0->dst_address.as_u64[1];
		}
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gre_rx_trace_t *tr = vlib_add_trace (vm, node,
						   b1, sizeof (*tr));
	      tr->tunnel_id = tunnel_sw_if_index;
	      if (!is_ipv6)
		{
		  tr->length = ip4_1->length;
		  tr->src.ip4.as_u32 = ip4_1->src_address.as_u32;
		  tr->dst.ip4.as_u32 = ip4_1->dst_address.as_u32;
		}
	      else
		{
		  tr->length = ip6_1->payload_length;
		  tr->src.ip6.as_u64[0] = ip6_1->src_address.as_u64[0];
		  tr->src.ip6.as_u64[1] = ip6_1->src_address.as_u64[1];
		  tr->dst.ip6.as_u64[0] = ip6_1->dst_address.as_u64[0];
		  tr->dst.ip6.as_u64[1] = ip6_1->dst_address.as_u64[1];
		}
	    }

	  vlib_buffer_advance (b0, sizeof (*h0));
	  vlib_buffer_advance (b1, sizeof (*h1));

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  gre_header_t *h0;
	  ip4_header_t *ip4_0;
	  ip6_header_t *ip6_0;
	  u16 version0;
	  int verr0;
	  u32 i0, next0;
	  u32 ip4_tun_src0, ip4_tun_dst0;
	  u32 ip6_tun_src0[4], ip6_tun_dst0[4];

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip4_0 = vlib_buffer_get_current (b0);
	  ip6_0 = (void *) ip4_0;

	  if (!is_ipv6)
	    {
	      ip4_tun_src0 = ip4_0->src_address.as_u32;
	      ip4_tun_dst0 = ip4_0->dst_address.as_u32;

	      vlib_buffer_advance (b0, sizeof (*ip4_0));
	    }
	  else
	    {
	      ip6_tun_src0[0] = ip6_0->src_address.as_u64[0];
	      ip6_tun_src0[1] = ip6_0->src_address.as_u64[1];
	      ip6_tun_dst0[0] = ip6_0->dst_address.as_u64[0];
	      ip6_tun_dst0[1] = ip6_0->dst_address.as_u64[1];

	      vlib_buffer_advance (b0, sizeof (*ip6_0));
	    }

	  h0 = vlib_buffer_get_current (b0);

	  i0 = sparse_vec_index (gm->next_by_protocol, h0->protocol);
	  next0 = vec_elt (gm->next_by_protocol, i0);

	  b0->error =
	    node->errors[i0 == SPARSE_VEC_INVALID_INDEX
			 ? GRE_ERROR_UNKNOWN_PROTOCOL : GRE_ERROR_NONE];

	  version0 = clib_net_to_host_u16 (h0->flags_and_version);
	  verr0 = version0 & GRE_VERSION_MASK;
	  b0->error = verr0 ? node->errors[GRE_ERROR_UNSUPPORTED_VERSION]
	    : b0->error;
	  next0 = verr0 ? GRE_INPUT_NEXT_DROP : next0;


	  /* For IP payload we need to find source interface
	     so we can increase counters and help forward node to
	     pick right FIB */
	  /* RPF check for ip4/ip6 input */
	  if (PREDICT_TRUE (next0 == GRE_INPUT_NEXT_IP4_INPUT
			    || next0 == GRE_INPUT_NEXT_IP6_INPUT
			    || next0 == GRE_INPUT_NEXT_ETHERNET_INPUT
			    || next0 == GRE_INPUT_NEXT_MPLS_INPUT))
	    {
	      u64 key4, key6[4];
	      if (!is_ipv6)
		{
		  key4 = ((u64) (ip4_tun_dst0) << 32) | (u64) (ip4_tun_src0);
		}
	      else
		{
		  key6[0] = ip6_tun_dst0[0];
		  key6[1] = ip6_tun_dst0[1];
		  key6[2] = ip6_tun_src0[0];
		  key6[3] = ip6_tun_src0[1];
		}

	      if ((!is_ipv6 && cached_tunnel_key4 != key4) ||
		  (is_ipv6 && cached_tunnel_key6[0] != key6[0] &&
		   cached_tunnel_key6[1] != key6[1] &&
		   cached_tunnel_key6[2] != key6[2] &&
		   cached_tunnel_key6[3] != key6[3]))
		{
		  vnet_hw_interface_t *hi;
		  gre_tunnel_t *t;
		  uword *p;

		  if (!is_ipv6)
		    p = hash_get (gm->tunnel_by_key4, key4);
		  else
		    p = hash_get_mem (gm->tunnel_by_key6, key6);

		  if (!p)
		    {
		      next0 = GRE_INPUT_NEXT_DROP;
		      b0->error = node->errors[GRE_ERROR_NO_SUCH_TUNNEL];
		      goto drop;
		    }
		  t = pool_elt_at_index (gm->tunnels, p[0]);
		  hi = vnet_get_hw_interface (gm->vnet_main, t->hw_if_index);
		  tunnel_sw_if_index = hi->sw_if_index;

		  cached_tunnel_sw_if_index = tunnel_sw_if_index;
		}
	      else
		{
		  tunnel_sw_if_index = cached_tunnel_sw_if_index;
		}
	    }
	  else
	    {
	      next0 = GRE_INPUT_NEXT_DROP;
	      goto drop;
	    }
	  len = vlib_buffer_length_in_chain (vm, b0);
	  vlib_increment_combined_counter (im->combined_sw_if_counters
					   + VNET_INTERFACE_COUNTER_RX,
					   thread_index,
					   tunnel_sw_if_index,
					   1 /* packets */ ,
					   len /* bytes */ );

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;

	drop:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gre_rx_trace_t *tr = vlib_add_trace (vm, node,
						   b0, sizeof (*tr));
	      tr->tunnel_id = tunnel_sw_if_index;
	      if (!is_ipv6)
		{
		  tr->length = ip4_0->length;
		  tr->src.ip4.as_u32 = ip4_0->src_address.as_u32;
		  tr->dst.ip4.as_u32 = ip4_0->dst_address.as_u32;
		}
	      else
		{
		  tr->length = ip6_0->payload_length;
		  tr->src.ip6.as_u64[0] = ip6_0->src_address.as_u64[0];
		  tr->src.ip6.as_u64[1] = ip6_0->src_address.as_u64[1];
		  tr->dst.ip6.as_u64[0] = ip6_0->dst_address.as_u64[0];
		  tr->dst.ip6.as_u64[1] = ip6_0->dst_address.as_u64[1];
		}
	    }

	  vlib_buffer_advance (b0, sizeof (*h0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm,
			       !is_ipv6 ? gre4_input_node.index :
			       gre6_input_node.index, GRE_ERROR_PKTS_DECAP,
			       from_frame->n_vectors);
  return from_frame->n_vectors;
}

static uword
gre4_input (vlib_main_t * vm,
	    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return gre_input (vm, node, from_frame, /* is_ip6 */ 0);
}

static uword
gre6_input (vlib_main_t * vm,
	    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return gre_input (vm, node, from_frame, /* is_ip6 */ 1);
}

static char *gre_error_strings[] = {
#define gre_error(n,s) s,
#include "error.def"
#undef gre_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gre4_input_node) = {
  .function = gre4_input,
  .name = "gre4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = GRE_N_ERROR,
  .error_strings = gre_error_strings,

  .n_next_nodes = GRE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [GRE_INPUT_NEXT_##s] = n,
    foreach_gre_input_next
#undef _
  },

  .format_buffer = format_gre_header_with_length,
  .format_trace = format_gre_rx_trace,
  .unformat_buffer = unformat_gre_header,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gre6_input_node) = {
  .function = gre6_input,
  .name = "gre6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof (gre_input_runtime_t),

  .n_errors = GRE_N_ERROR,
  .error_strings = gre_error_strings,

  .n_next_nodes = GRE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [GRE_INPUT_NEXT_##s] = n,
    foreach_gre_input_next
#undef _
  },

  .format_buffer = format_gre_header_with_length,
  .format_trace = format_gre_rx_trace,
  .unformat_buffer = unformat_gre_header,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (gre4_input_node, gre4_input)
VLIB_NODE_FUNCTION_MULTIARCH (gre6_input_node, gre6_input)
     void
       gre_register_input_protocol (vlib_main_t * vm,
				    gre_protocol_t protocol, u32 node_index)
{
  gre_main_t *em = &gre_main;
  gre_protocol_info_t *pi;
  u16 *n;
  u32 i;

  {
    clib_error_t *error = vlib_call_init_function (vm, gre_input_init);
    if (error)
      clib_error_report (error);
  }

  pi = gre_get_protocol_info (em, protocol);
  pi->node_index = node_index;
  pi->next_index = vlib_node_add_next (vm, gre4_input_node.index, node_index);
  i = vlib_node_add_next (vm, gre6_input_node.index, node_index);
  ASSERT (i == pi->next_index);

  /* Setup gre protocol -> next index sparse vector mapping. */
  n = sparse_vec_validate (em->next_by_protocol,
			   clib_host_to_net_u16 (protocol));
  n[0] = pi->next_index;
}

static void
gre_setup_node (vlib_main_t * vm, u32 node_index)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  pg_node_t *pn = pg_get_node (node_index);

  n->format_buffer = format_gre_header_with_length;
  n->unformat_buffer = unformat_gre_header;
  pn->unformat_edit = unformat_pg_gre_header;
}

static clib_error_t *
gre_input_init (vlib_main_t * vm)
{
  gre_main_t *gm = &gre_main;
  vlib_node_t *ethernet_input, *ip4_input, *ip6_input, *mpls_unicast_input;

  {
    clib_error_t *error;
    error = vlib_call_init_function (vm, gre_init);
    if (error)
      clib_error_report (error);
  }

  gre_setup_node (vm, gre4_input_node.index);
  gre_setup_node (vm, gre6_input_node.index);

  gm->next_by_protocol = sparse_vec_new
    ( /* elt bytes */ sizeof (gm->next_by_protocol[0]),
     /* bits in index */ BITS (((gre_header_t *) 0)->protocol));

  /* These could be moved to the supported protocol input node defn's */
  ethernet_input = vlib_get_node_by_name (vm, (u8 *) "ethernet-input");
  ASSERT (ethernet_input);
  ip4_input = vlib_get_node_by_name (vm, (u8 *) "ip4-input");
  ASSERT (ip4_input);
  ip6_input = vlib_get_node_by_name (vm, (u8 *) "ip6-input");
  ASSERT (ip6_input);
  mpls_unicast_input = vlib_get_node_by_name (vm, (u8 *) "mpls-input");
  ASSERT (mpls_unicast_input);

  gre_register_input_protocol (vm, GRE_PROTOCOL_teb, ethernet_input->index);

  gre_register_input_protocol (vm, GRE_PROTOCOL_ip4, ip4_input->index);

  gre_register_input_protocol (vm, GRE_PROTOCOL_ip6, ip6_input->index);

  gre_register_input_protocol (vm, GRE_PROTOCOL_mpls_unicast,
			       mpls_unicast_input->index);

  ip4_register_protocol (IP_PROTOCOL_GRE, gre4_input_node.index);
  ip6_register_protocol (IP_PROTOCOL_GRE, gre6_input_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (gre_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

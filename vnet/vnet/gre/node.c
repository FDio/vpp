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

typedef enum {
#define _(s,n) GRE_INPUT_NEXT_##s,
  foreach_gre_input_next
#undef _
  GRE_INPUT_N_NEXT,
} gre_input_next_t;

typedef struct {
  u32 tunnel_id;
  u32 length;
  ip4_address_t src;
  ip4_address_t dst;
} gre_rx_trace_t;

u8 * format_gre_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gre_rx_trace_t * t = va_arg (*args, gre_rx_trace_t *);
    
  s = format (s, "GRE: tunnel %d len %d src %U dst %U",
              t->tunnel_id, clib_net_to_host_u16(t->length),
              format_ip4_address, &t->src.as_u8,
              format_ip4_address, &t->dst.as_u8);
  return s;
}

typedef struct {
  /* Sparse vector mapping gre protocol in network byte order
     to next index. */
  u16 * next_by_protocol;
} gre_input_runtime_t;

static uword
gre_input (vlib_main_t * vm,
	   vlib_node_runtime_t * node,
	   vlib_frame_t * from_frame)
{
  gre_main_t * gm = &gre_main;
  gre_input_runtime_t * rt = (void *) node->runtime_data;
  __attribute__((unused)) u32 n_left_from, next_index, * from, * to_next;
  u64 cached_tunnel_key = (u64) ~0;
  u32 cached_tunnel_sw_if_index = 0, tunnel_sw_if_index = 0;

  u32 cpu_index = os_get_cpu_number();
  u32 len;
  vnet_interface_main_t *im = &gm->vnet_main->interface_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
	  gre_header_t * h0, * h1;
          u16 version0, version1;
          int verr0, verr1;
	  u32 i0, i1, next0, next1, protocol0, protocol1;
          ip4_header_t *ip0, *ip1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

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

          /* ip4_local hands us the ip header, not the gre header */
          ip0 = vlib_buffer_get_current (b0);
          ip1 = vlib_buffer_get_current (b1);

          /* Save src + dst ip4 address, e.g. for mpls-o-gre */
          vnet_buffer(b0)->gre.src = ip0->src_address.as_u32;
          vnet_buffer(b0)->gre.dst = ip0->dst_address.as_u32;
          vnet_buffer(b1)->gre.src = ip1->src_address.as_u32;
          vnet_buffer(b1)->gre.dst = ip1->dst_address.as_u32;

          vlib_buffer_advance (b0, sizeof (*ip0));
          vlib_buffer_advance (b1, sizeof (*ip1));

	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);

	  /* Index sparse array with network byte order. */
	  protocol0 = h0->protocol;
	  protocol1 = h1->protocol;
	  sparse_vec_index2 (rt->next_by_protocol, protocol0, protocol1,
                             &i0, &i1);
          next0 = vec_elt(rt->next_by_protocol, i0);
          next1 = vec_elt(rt->next_by_protocol, i1);

	  b0->error = node->errors[i0 == SPARSE_VEC_INVALID_INDEX ? GRE_ERROR_UNKNOWN_PROTOCOL : GRE_ERROR_NONE];
	  b1->error = node->errors[i1 == SPARSE_VEC_INVALID_INDEX ? GRE_ERROR_UNKNOWN_PROTOCOL : GRE_ERROR_NONE];
          
          version0 = clib_net_to_host_u16 (h0->flags_and_version);
          verr0 =  version0 & GRE_VERSION_MASK;
          version1 = clib_net_to_host_u16 (h1->flags_and_version);
          verr1 =  version1 & GRE_VERSION_MASK;

          b0->error = verr0 ? node->errors[GRE_ERROR_UNSUPPORTED_VERSION]
              : b0->error;
          next0 = verr0 ? GRE_INPUT_NEXT_DROP : next0;
          b1->error = verr1 ? node->errors[GRE_ERROR_UNSUPPORTED_VERSION]
              : b1->error;
          next1 = verr1 ? GRE_INPUT_NEXT_DROP : next1;


          /* RPF check for ip4/ip6 input */
          if (PREDICT_TRUE(next0 == GRE_INPUT_NEXT_IP4_INPUT
			   || next0 == GRE_INPUT_NEXT_IP6_INPUT
			   || next0 == GRE_INPUT_NEXT_ETHERNET_INPUT
			   || next0 == GRE_INPUT_NEXT_MPLS_INPUT))
            {
              u64 key = ((u64)(vnet_buffer(b0)->gre.dst) << 32) |
                         (u64)(vnet_buffer(b0)->gre.src);

              if (cached_tunnel_key != key)
                {
                  vnet_hw_interface_t * hi;
                  gre_tunnel_t * t;
                  uword * p;

                  p = hash_get (gm->tunnel_by_key, key);
                  if (!p)
                    {
                      next0 = GRE_INPUT_NEXT_DROP;
                      b0->error = node->errors[GRE_ERROR_NO_SUCH_TUNNEL];
                      goto drop0;
                    }
                  t = pool_elt_at_index (gm->tunnels, p[0]);
                  hi = vnet_get_hw_interface (gm->vnet_main,
                            t->hw_if_index);
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
                                           cpu_index,
                                           tunnel_sw_if_index,
                                           1 /* packets */,
                                           len /* bytes */);

          vnet_buffer(b0)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;

drop0:
          if (PREDICT_TRUE(next1 == GRE_INPUT_NEXT_IP4_INPUT
			   || next1 == GRE_INPUT_NEXT_IP6_INPUT
			   || next1 == GRE_INPUT_NEXT_ETHERNET_INPUT
			   || next1 == GRE_INPUT_NEXT_MPLS_INPUT))
            {
              u64 key = ((u64)(vnet_buffer(b1)->gre.dst) << 32) |
                         (u64)(vnet_buffer(b1)->gre.src);

              if (cached_tunnel_key != key)
                {
                  vnet_hw_interface_t * hi;
                  gre_tunnel_t * t;
                  uword * p;

                  p = hash_get (gm->tunnel_by_key, key);
                  if (!p)
                    {
                      next1 = GRE_INPUT_NEXT_DROP;
                      b1->error = node->errors[GRE_ERROR_NO_SUCH_TUNNEL];
                      goto drop1;
                    }
                  t = pool_elt_at_index (gm->tunnels, p[0]);
                  hi = vnet_get_hw_interface (gm->vnet_main,
                            t->hw_if_index);
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
                                           cpu_index,
                                           tunnel_sw_if_index,
                                           1 /* packets */,
                                           len /* bytes */);

          vnet_buffer(b1)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;

drop1:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              gre_rx_trace_t *tr = vlib_add_trace (vm, node,
                                                   b0, sizeof (*tr));
              tr->tunnel_id = tunnel_sw_if_index;
              tr->length = ip0->length;
              tr->src.as_u32 = ip0->src_address.as_u32;
              tr->dst.as_u32 = ip0->dst_address.as_u32;
            }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              gre_rx_trace_t *tr = vlib_add_trace (vm, node,
                                                   b1, sizeof (*tr));
              tr->tunnel_id = tunnel_sw_if_index;
              tr->length = ip1->length;
              tr->src.as_u32 = ip1->src_address.as_u32;
              tr->dst.as_u32 = ip1->dst_address.as_u32;
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
	  vlib_buffer_t * b0;
	  gre_header_t * h0;
          ip4_header_t * ip0;
          u16 version0;
          int verr0;
	  u32 i0, next0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          ip0 = vlib_buffer_get_current (b0);

          vnet_buffer(b0)->gre.src = ip0->src_address.as_u32;
          vnet_buffer(b0)->gre.dst = ip0->dst_address.as_u32;

          vlib_buffer_advance (b0, sizeof (*ip0));

	  h0 = vlib_buffer_get_current (b0);

	  i0 = sparse_vec_index (rt->next_by_protocol, h0->protocol);
          next0 = vec_elt(rt->next_by_protocol, i0);

	  b0->error = 
              node->errors[i0 == SPARSE_VEC_INVALID_INDEX 
                           ? GRE_ERROR_UNKNOWN_PROTOCOL : GRE_ERROR_NONE];
	  
          version0 = clib_net_to_host_u16 (h0->flags_and_version);
          verr0 =  version0 & GRE_VERSION_MASK;
          b0->error = verr0 ? node->errors[GRE_ERROR_UNSUPPORTED_VERSION] 
              : b0->error;
          next0 = verr0 ? GRE_INPUT_NEXT_DROP : next0;


          /* For IP payload we need to find source interface
             so we can increase counters and help forward node to
             pick right FIB */
          /* RPF check for ip4/ip6 input */
          if (PREDICT_TRUE(next0 == GRE_INPUT_NEXT_IP4_INPUT
			   || next0 == GRE_INPUT_NEXT_IP6_INPUT
			   || next0 == GRE_INPUT_NEXT_ETHERNET_INPUT
			   || next0 == GRE_INPUT_NEXT_MPLS_INPUT))
            {
              u64 key = ((u64)(vnet_buffer(b0)->gre.dst) << 32) |
                         (u64)(vnet_buffer(b0)->gre.src);

              if (cached_tunnel_key != key)
                {
                  vnet_hw_interface_t * hi;
                  gre_tunnel_t * t;
                  uword * p;

                  p = hash_get (gm->tunnel_by_key, key);
                  if (!p)
                    {
                      next0 = GRE_INPUT_NEXT_DROP;
                      b0->error = node->errors[GRE_ERROR_NO_SUCH_TUNNEL];
                      goto drop;
                    }
                  t = pool_elt_at_index (gm->tunnels, p[0]);
                  hi = vnet_get_hw_interface (gm->vnet_main,
                            t->hw_if_index);
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
                                           cpu_index,
                                           tunnel_sw_if_index,
                                           1 /* packets */,
                                           len /* bytes */);

          vnet_buffer(b0)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;

drop:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              gre_rx_trace_t *tr = vlib_add_trace (vm, node, 
                                                   b0, sizeof (*tr));
              tr->tunnel_id = tunnel_sw_if_index;
              tr->length = ip0->length;
              tr->src.as_u32 = ip0->src_address.as_u32;
              tr->dst.as_u32 = ip0->dst_address.as_u32;
            }

          vlib_buffer_advance (b0, sizeof (*h0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, gre_input_node.index,
                               GRE_ERROR_PKTS_DECAP, from_frame->n_vectors);
  return from_frame->n_vectors;
}

static char * gre_error_strings[] = {
#define gre_error(n,s) s,
#include "error.def"
#undef gre_error
};

VLIB_REGISTER_NODE (gre_input_node) = {
  .function = gre_input,
  .name = "gre-input",
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

VLIB_NODE_FUNCTION_MULTIARCH (gre_input_node, gre_input)

void
gre_register_input_protocol (vlib_main_t * vm,
			     gre_protocol_t protocol,
			     u32 node_index)
{
  gre_main_t * em = &gre_main;
  gre_protocol_info_t * pi;
  gre_input_runtime_t * rt;
  u16 * n;

  {
    clib_error_t * error = vlib_call_init_function (vm, gre_input_init);
    if (error)
      clib_error_report (error);
  }

  pi = gre_get_protocol_info (em, protocol);
  pi->node_index = node_index;
  pi->next_index = vlib_node_add_next (vm, 
				       gre_input_node.index,
				       node_index);

  /* Setup gre protocol -> next index sparse vector mapping. */
  rt = vlib_node_get_runtime_data (vm, gre_input_node.index);
  n = sparse_vec_validate (rt->next_by_protocol, 
                           clib_host_to_net_u16 (protocol));
  n[0] = pi->next_index;
}

static void
gre_setup_node (vlib_main_t * vm, u32 node_index)
{
  vlib_node_t * n = vlib_get_node (vm, node_index);
  pg_node_t * pn = pg_get_node (node_index);

  n->format_buffer = format_gre_header_with_length;
  n->unformat_buffer = unformat_gre_header;
  pn->unformat_edit = unformat_pg_gre_header;
}

static clib_error_t * gre_input_init (vlib_main_t * vm)
{
  gre_input_runtime_t * rt;
  vlib_node_t *ethernet_input, *ip4_input, *ip6_input, *mpls_unicast_input;

  {
    clib_error_t * error; 
    error = vlib_call_init_function (vm, gre_init);
    if (error)
      clib_error_report (error);
  }

  gre_setup_node (vm, gre_input_node.index);

  rt = vlib_node_get_runtime_data (vm, gre_input_node.index);

  rt->next_by_protocol = sparse_vec_new
    (/* elt bytes */ sizeof (rt->next_by_protocol[0]),
     /* bits in index */ BITS (((gre_header_t *) 0)->protocol));

  /* These could be moved to the supported protocol input node defn's */
  ethernet_input = vlib_get_node_by_name (vm, (u8 *)"ethernet-input");
  ASSERT(ethernet_input);
  ip4_input = vlib_get_node_by_name (vm, (u8 *)"ip4-input");
  ASSERT(ip4_input);
  ip6_input = vlib_get_node_by_name (vm, (u8 *)"ip6-input");
  ASSERT(ip6_input);
  mpls_unicast_input = vlib_get_node_by_name (vm, (u8 *)"mpls-input");
  ASSERT(mpls_unicast_input);

  gre_register_input_protocol (vm, GRE_PROTOCOL_teb,
                               ethernet_input->index);

  gre_register_input_protocol (vm, GRE_PROTOCOL_ip4, 
                               ip4_input->index);

  gre_register_input_protocol (vm, GRE_PROTOCOL_ip6, 
                               ip6_input->index);

  gre_register_input_protocol (vm, GRE_PROTOCOL_mpls_unicast,
                               mpls_unicast_input->index);

  ip4_register_protocol (IP_PROTOCOL_GRE, gre_input_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (gre_input_init);

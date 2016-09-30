/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief L2-GRE over IPSec packet processing.
 *
 * Removes GRE header from the packet and sends it to the l2-input node.
*/

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/ipsec-gre/ipsec_gre.h>
#include <vppinfra/sparse_vec.h>

#define foreach_ipsec_gre_input_next		\
_(PUNT, "error-punt")                           \
_(DROP, "error-drop")                           \
_(L2_INPUT, "l2-input")

typedef enum {
#define _(s,n) IPSEC_GRE_INPUT_NEXT_##s,
  foreach_ipsec_gre_input_next
#undef _
  IPSEC_GRE_INPUT_N_NEXT,
} ipsec_gre_input_next_t;

typedef struct {
  u32 tunnel_id;
  u32 length;
  ip4_address_t src;
  ip4_address_t dst;
} ipsec_gre_rx_trace_t;

u8 * format_ipsec_gre_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_gre_rx_trace_t * t = va_arg (*args, ipsec_gre_rx_trace_t *);

  s = format (s, "GRE: tunnel %d len %d src %U dst %U",
              t->tunnel_id, clib_net_to_host_u16(t->length),
              format_ip4_address, &t->src.as_u8,
              format_ip4_address, &t->dst.as_u8);
  return s;
}

/**
 * @brief L2-GRE over IPSec input node.
 * @node ipsec-gre-input
 *
 * This node remove GRE header.
 *
 * @param vm         vlib_main_t corresponding to the current thread.
 * @param node       vlib_node_runtime_t data for this node.
 * @param from_frame vlib_frame_t whose contents should be dispatched.
 *
 * @par Graph mechanics: buffer metadata, next index usage
 *
 * <em>Uses:</em>
 * - <code>ip->src_address</code> and <code>ip->dst_address</code>
 *     - Match tunnel by source and destination addresses in GRE IP header.
 *
 * <em>Sets:</em>
 * - <code>vnet_buffer(b)->gre.src</code>
 *     - Save tunnel source IPv4 address.
 * - <code>vnet_buffer(b)->gre.dst</code>
 *     - Save tunnel destination IPv4 address.
 * - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
 *     - Set input sw_if_index to IPSec-GRE tunnel for learning.
 *
 * <em>Next Index:</em>
 * - Dispatches the packet to the l2-input node.
*/
static uword
ipsec_gre_input (vlib_main_t * vm,
                 vlib_node_runtime_t * node,
                 vlib_frame_t * from_frame)
{
  ipsec_gre_main_t * igm = &ipsec_gre_main;
  u32 n_left_from, next_index, * from, * to_next;
  u64 cached_tunnel_key = (u64) ~0;
  u32 cached_tunnel_sw_if_index = 0, tunnel_sw_if_index;
  u32 tun_src0, tun_dst0;
  u32 tun_src1, tun_dst1;

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
          u16 version0, version1, protocol0, protocol1;
          int verr0, verr1;
	  u32 next0, next1;
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

          /* Save src + dst ip4 address */
          tun_src0 = ip0->src_address.as_u32;
          tun_dst0 = ip0->dst_address.as_u32;
          tun_src1 = ip1->src_address.as_u32;
          tun_dst1 = ip1->dst_address.as_u32;

          vlib_buffer_advance (b0, sizeof (*ip0));
          vlib_buffer_advance (b1, sizeof (*ip1));

	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);

          protocol0 = clib_net_to_host_u16 (h0->protocol);
          protocol1 = clib_net_to_host_u16 (h1->protocol);
          if (PREDICT_TRUE(protocol0 == 0x0001))
            {
              next0 = IPSEC_GRE_INPUT_NEXT_L2_INPUT;
              b0->error = node->errors[IPSEC_GRE_ERROR_NONE];
            }
          else
            {
              clib_warning("unknown GRE protocol: %d", protocol0);
              b0->error = node->errors[IPSEC_GRE_ERROR_UNKNOWN_PROTOCOL];
              next0 = IPSEC_GRE_INPUT_NEXT_DROP;
            }
          if (PREDICT_TRUE(protocol1 == 0x0001))
            {
              next1 = IPSEC_GRE_INPUT_NEXT_L2_INPUT;
              b1->error = node->errors[IPSEC_GRE_ERROR_NONE];
            }
          else
            {
              clib_warning("unknown GRE protocol: %d", protocol1);
              b1->error = node->errors[IPSEC_GRE_ERROR_UNKNOWN_PROTOCOL];
              next1 = IPSEC_GRE_INPUT_NEXT_DROP;
            }

          version0 = clib_net_to_host_u16 (h0->flags_and_version);
          verr0 =  version0 & GRE_VERSION_MASK;
          version1 = clib_net_to_host_u16 (h1->flags_and_version);
          verr1 =  version1 & GRE_VERSION_MASK;

          b0->error = verr0 ? node->errors[IPSEC_GRE_ERROR_UNSUPPORTED_VERSION]
              : b0->error;
          next0 = verr0 ? IPSEC_GRE_INPUT_NEXT_DROP : next0;
          b1->error = verr1 ? node->errors[IPSEC_GRE_ERROR_UNSUPPORTED_VERSION]
              : b1->error;
          next1 = verr1 ? IPSEC_GRE_INPUT_NEXT_DROP : next1;

          /* For L2 payload set input sw_if_index to GRE tunnel for learning */
          if (PREDICT_TRUE(next0 == IPSEC_GRE_INPUT_NEXT_L2_INPUT))
            {
              u64 key = ((u64)(tun_dst0) << 32) | (u64)(tun_src0);

              if (cached_tunnel_key != key)
                {
                  vnet_hw_interface_t * hi;
                  ipsec_gre_tunnel_t * t;
                  uword * p;

                  p = hash_get (igm->tunnel_by_key, key);
                  if (!p)
                    {
                      next0 = IPSEC_GRE_INPUT_NEXT_DROP;
                      b0->error = node->errors[IPSEC_GRE_ERROR_NO_SUCH_TUNNEL];
                      goto drop0;
                    }
                  t = pool_elt_at_index (igm->tunnels, p[0]);
                  hi = vnet_get_hw_interface (igm->vnet_main,
                            t->hw_if_index);
                  tunnel_sw_if_index = hi->sw_if_index;
                  cached_tunnel_sw_if_index = tunnel_sw_if_index;
                }
              else
                {
                  tunnel_sw_if_index = cached_tunnel_sw_if_index;
                }
              vnet_buffer(b0)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;
            }

drop0:
          /* For L2 payload set input sw_if_index to GRE tunnel for learning */
          if (PREDICT_TRUE(next1 == IPSEC_GRE_INPUT_NEXT_L2_INPUT))
            {
              u64 key = ((u64)(tun_dst1) << 32) | (u64)(tun_src1);

              if (cached_tunnel_key != key)
                {
                  vnet_hw_interface_t * hi;
                  ipsec_gre_tunnel_t * t;
                  uword * p;

                  p = hash_get (igm->tunnel_by_key, key);
                  if (!p)
                    {
                      next1 = IPSEC_GRE_INPUT_NEXT_DROP;
                      b1->error = node->errors[IPSEC_GRE_ERROR_NO_SUCH_TUNNEL];
                      goto drop1;
                    }
                  t = pool_elt_at_index (igm->tunnels, p[0]);
                  hi = vnet_get_hw_interface (igm->vnet_main,
                            t->hw_if_index);
                  tunnel_sw_if_index = hi->sw_if_index;
                  cached_tunnel_sw_if_index = tunnel_sw_if_index;
                }
              else
                {
                  tunnel_sw_if_index = cached_tunnel_sw_if_index;
                }
              vnet_buffer(b1)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;
            }

drop1:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              ipsec_gre_rx_trace_t *tr = vlib_add_trace (vm, node,
                                                   b0, sizeof (*tr));
              tr->tunnel_id = ~0;
              tr->length = ip0->length;
              tr->src.as_u32 = ip0->src_address.as_u32;
              tr->dst.as_u32 = ip0->dst_address.as_u32;
            }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              ipsec_gre_rx_trace_t *tr = vlib_add_trace (vm, node,
                                                   b1, sizeof (*tr));
              tr->tunnel_id = ~0;
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
          u16 version0, protocol0;
          int verr0;
	  u32 next0;
	  u32 tun_src0, tun_dst0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          ip0 = vlib_buffer_get_current (b0);

          tun_src0 = ip0->src_address.as_u32;
          tun_dst0 = ip0->dst_address.as_u32;

          vlib_buffer_advance (b0, sizeof (*ip0));

	  h0 = vlib_buffer_get_current (b0);

          protocol0 = clib_net_to_host_u16 (h0->protocol);
          if (PREDICT_TRUE(protocol0 == 0x0001))
            {
              next0 = IPSEC_GRE_INPUT_NEXT_L2_INPUT;
              b0->error = node->errors[IPSEC_GRE_ERROR_NONE];
            }
          else
            {
              clib_warning("unknown GRE protocol: %d", protocol0);
              b0->error = node->errors[IPSEC_GRE_ERROR_UNKNOWN_PROTOCOL];
              next0 = IPSEC_GRE_INPUT_NEXT_DROP;
            }

          version0 = clib_net_to_host_u16 (h0->flags_and_version);
          verr0 =  version0 & GRE_VERSION_MASK;
          b0->error = verr0 ? node->errors[IPSEC_GRE_ERROR_UNSUPPORTED_VERSION]
              : b0->error;
          next0 = verr0 ? IPSEC_GRE_INPUT_NEXT_DROP : next0;

          /* For L2 payload set input sw_if_index to GRE tunnel for learning */
          if (PREDICT_FALSE(next0 == IPSEC_GRE_INPUT_NEXT_L2_INPUT))
            {
              u64 key = ((u64)(tun_dst0) << 32) | (u64)(tun_src0);

              if (cached_tunnel_key != key)
                {
                  vnet_hw_interface_t * hi;
                  ipsec_gre_tunnel_t * t;
                  uword * p;

                  p = hash_get (igm->tunnel_by_key, key);
                  if (!p)
                    {
                      next0 = IPSEC_GRE_INPUT_NEXT_DROP;
                      b0->error = node->errors[IPSEC_GRE_ERROR_NO_SUCH_TUNNEL];
                      goto drop;
                    }
                  t = pool_elt_at_index (igm->tunnels, p[0]);
                  hi = vnet_get_hw_interface (igm->vnet_main,
                            t->hw_if_index);
                  tunnel_sw_if_index = hi->sw_if_index;
                  cached_tunnel_sw_if_index = tunnel_sw_if_index;
                }
              else
                {
                  tunnel_sw_if_index = cached_tunnel_sw_if_index;
                }
              vnet_buffer(b0)->sw_if_index[VLIB_RX] = tunnel_sw_if_index;
            }

drop:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              ipsec_gre_rx_trace_t *tr = vlib_add_trace (vm, node,
                                                   b0, sizeof (*tr));
              tr->tunnel_id = ~0;
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
  vlib_node_increment_counter (vm, ipsec_gre_input_node.index,
                               IPSEC_GRE_ERROR_PKTS_DECAP, from_frame->n_vectors);
  return from_frame->n_vectors;
}

static char * ipsec_gre_error_strings[] = {
#define ipsec_gre_error(n,s) s,
#include "error.def"
#undef ipsec_gre_error
};

VLIB_REGISTER_NODE (ipsec_gre_input_node) = {
  .function = ipsec_gre_input,
  .name = "ipsec-gre-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = IPSEC_GRE_N_ERROR,
  .error_strings = ipsec_gre_error_strings,

  .n_next_nodes = IPSEC_GRE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [IPSEC_GRE_INPUT_NEXT_##s] = n,
    foreach_ipsec_gre_input_next
#undef _
  },

  .format_trace = format_ipsec_gre_rx_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ipsec_gre_input_node, ipsec_gre_input)

static clib_error_t * ipsec_gre_input_init (vlib_main_t * vm)
{
  {
    clib_error_t * error;
    error = vlib_call_init_function (vm, ipsec_gre_init);
    if (error)
      clib_error_report (error);
  }

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_gre_input_init);

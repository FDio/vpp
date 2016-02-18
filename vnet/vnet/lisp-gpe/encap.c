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

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/udp.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

/* Statistics (not really errors) */
#define foreach_lisp_gpe_encap_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char * lisp_gpe_encap_error_strings[] = {
#define _(sym,string) string,
  foreach_lisp_gpe_encap_error
#undef _
};

typedef enum {
#define _(sym,str) LISP_GPE_ENCAP_ERROR_##sym,
  foreach_lisp_gpe_encap_error
#undef _
  LISP_GPE_ENCAP_N_ERROR,
} lisp_gpe_encap_error_t;

typedef enum
{
  LISP_GPE_ENCAP_NEXT_DROP,
  LISP_GPE_ENCAP_NEXT_IP4_LOOKUP,
  LISP_GPE_ENCAP_N_NEXT,
} lisp_gpe_encap_next_t;

typedef struct
{
  u32 tunnel_index;
} lisp_gpe_encap_trace_t;

u8 *
format_lisp_gpe_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lisp_gpe_encap_trace_t * t = va_arg (*args, lisp_gpe_encap_trace_t *);

  s = format (s, "LISP-GPE-ENCAP: tunnel %d", t->tunnel_index);
  return s;
}

static uword
lisp_gpe_encap (vlib_main_t * vm, vlib_node_runtime_t * node,
                vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  u32 pkts_encapsulated = 0;

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
          u32 next0, next1;
          u32 adj_index0, adj_index1, tunnel_index0, tunnel_index1;
          ip_adjacency_t * adj0, * adj1;
          lisp_gpe_tunnel_t * t0, * t1;

          next0 = next1 = LISP_GPE_ENCAP_NEXT_IP4_LOOKUP;

          /* Prefetch next iteration. */
            {
              vlib_buffer_t * p2, *p3;

              p2 = vlib_get_buffer (vm, from[2]);
              p3 = vlib_get_buffer (vm, from[3]);

              vlib_prefetch_buffer_header(p2, LOAD);
              vlib_prefetch_buffer_header(p3, LOAD);

              CLIB_PREFETCH(p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
              CLIB_PREFETCH(p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
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

          /* Get adjacency and from it the tunnel_index */
          adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
          adj_index1 = vnet_buffer(b1)->ip.adj_index[VLIB_TX];

          adj0 = ip_get_adjacency (lgm->lookup_main, adj_index0);
          adj1 = ip_get_adjacency (lgm->lookup_main, adj_index1);

          tunnel_index0 = adj0->rewrite_header.sw_if_index;
          tunnel_index1 = adj1->rewrite_header.sw_if_index;

          t0 = pool_elt_at_index (lgm->tunnels, tunnel_index0);
          t1 = pool_elt_at_index (lgm->tunnels, tunnel_index1);

          ASSERT(t0 != 0);
          ASSERT(t1 != 0);

          ASSERT (sizeof(ip4_udp_lisp_gpe_header_t) == 36);
          ip4_udp_encap_two (vm, b0, b1, t0->rewrite, t1->rewrite, 36);

          /* Reset to look up tunnel partner in the configured FIB */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->encap_fib_index;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              lisp_gpe_encap_trace_t *tr = vlib_add_trace (vm, node, b0,
                                                           sizeof(*tr));
              tr->tunnel_index = t0 - lgm->tunnels;
            }
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              lisp_gpe_encap_trace_t *tr = vlib_add_trace (vm, node, b1,
                                                           sizeof(*tr));
              tr->tunnel_index = t1 - lgm->tunnels;
            }

          pkts_encapsulated += 2;

          vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, bi1, next0,
                                          next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          vlib_buffer_t * b0;
          u32 bi0, adj_index0, tunnel_index0;
          u32 next0 = LISP_GPE_ENCAP_NEXT_IP4_LOOKUP;
          lisp_gpe_tunnel_t * t0 = 0;
          ip_adjacency_t * adj0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          /* Get adjacency and from it the tunnel_index */
          adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
          adj0 = ip_get_adjacency (lgm->lookup_main, adj_index0);

          tunnel_index0 = adj0->rewrite_header.sw_if_index;
          t0 = pool_elt_at_index (lgm->tunnels, tunnel_index0);

          ASSERT(t0 != 0);

          ASSERT (sizeof(ip4_udp_lisp_gpe_header_t) == 36);
          ip4_udp_encap_one (vm, b0, t0->rewrite, 36);

          /* Reset to look up tunnel partner in the configured FIB */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;

          pkts_encapsulated++;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              lisp_gpe_encap_trace_t *tr = vlib_add_trace (vm, node, b0,
                                                           sizeof(*tr));
              tr->tunnel_index = t0 - lgm->tunnels;
            }
          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index, 
                               LISP_GPE_ENCAP_ERROR_ENCAPSULATED, 
                               pkts_encapsulated);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (lisp_gpe_encap_node) = {
  .function = lisp_gpe_encap,
  .name = "lisp-gpe-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_lisp_gpe_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(lisp_gpe_encap_error_strings),
  .error_strings = lisp_gpe_encap_error_strings,

  .n_next_nodes = LISP_GPE_ENCAP_N_NEXT,

  .next_nodes = {
      [LISP_GPE_ENCAP_NEXT_DROP] = "error-drop",
      [LISP_GPE_ENCAP_NEXT_IP4_LOOKUP] = "ip4-lookup",
  },
};

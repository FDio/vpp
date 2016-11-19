/*
 * mpls_lookup.c: MPLS lookup
 *
 * Copyright (c) 2012-2014 Cisco and/or its affiliates.
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
#include <vnet/mpls/mpls.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/dpo/load_balance.h>

vlib_node_registration_t mpls_lookup_node;

typedef struct {
  u32 next_index;
  u32 lb_index;
  u32 lfib_index;
  u32 label_net_byte_order;
  u32 hash;
} mpls_lookup_trace_t;

static u8 *
format_mpls_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_lookup_trace_t * t = va_arg (*args, mpls_lookup_trace_t *);

  s = format (s, "MPLS: next [%d], lookup fib index %d, LB index %d hash %d"
              "label %d eos %d", 
              t->next_index, t->lfib_index, t->lb_index, t->hash,
              vnet_mpls_uc_get_label(
                  clib_net_to_host_u32(t->label_net_byte_order)),
              vnet_mpls_uc_get_s(t->label_net_byte_order));
  return s;
}

/*
 * Compute flow hash. 
 * We'll use it to select which adjacency to use for this flow.  And other things.
 */
always_inline u32
mpls_compute_flow_hash (const mpls_unicast_header_t * hdr,
                        flow_hash_config_t flow_hash_config)
{
    // FIXME
    return (vnet_mpls_uc_get_label(hdr->label_exp_s_ttl));
}

static inline uword
mpls_lookup (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
  vlib_combined_counter_main_t * cm = &load_balance_main.lbm_to_counters;
  u32 n_left_from, next_index, * from, * to_next;
  mpls_main_t * mm = &mpls_main;
  u32 cpu_index = os_get_cpu_number();

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
          u32 lbi0, next0, lfib_index0, bi0, hash_c0;
          const mpls_unicast_header_t * h0;
          const load_balance_t *lb0;
          const dpo_id_t *dpo0;
          vlib_buffer_t * b0;
          u32 lbi1, next1, lfib_index1, bi1, hash_c1;
          const mpls_unicast_header_t * h1;
          const load_balance_t *lb1;
          const dpo_id_t *dpo1;
          vlib_buffer_t * b1;

           /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, STORE);
            vlib_prefetch_buffer_header (p3, STORE);

            CLIB_PREFETCH (p2->data, sizeof (h0[0]), STORE);
            CLIB_PREFETCH (p3->data, sizeof (h0[0]), STORE);
          }

          bi0 = to_next[0] = from[0];
          bi1 = to_next[1] = from[1];

          from += 2;
          n_left_from -= 2;
          to_next += 2;
          n_left_to_next -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);
          h0 = vlib_buffer_get_current (b0);
          h1 = vlib_buffer_get_current (b1);

          lfib_index0 = vec_elt(mm->fib_index_by_sw_if_index,
                                vnet_buffer(b0)->sw_if_index[VLIB_RX]);
          lfib_index1 = vec_elt(mm->fib_index_by_sw_if_index,
                                vnet_buffer(b1)->sw_if_index[VLIB_RX]);

          lbi0 = mpls_fib_table_forwarding_lookup (lfib_index0, h0);
          lbi1 = mpls_fib_table_forwarding_lookup (lfib_index1, h1);
          lb0 = load_balance_get(lbi0);
          lb1 = load_balance_get(lbi1);

          hash_c0 = vnet_buffer(b0)->ip.flow_hash = 0;
          hash_c1 = vnet_buffer(b1)->ip.flow_hash = 0;

          if (PREDICT_FALSE(lb0->lb_n_buckets > 1))
          {
              hash_c0 = vnet_buffer (b0)->ip.flow_hash =
                  mpls_compute_flow_hash(h0, lb0->lb_hash_config);
          }
          if (PREDICT_FALSE(lb1->lb_n_buckets > 1))
          {
              hash_c1 = vnet_buffer (b1)->ip.flow_hash =
                  mpls_compute_flow_hash(h1, lb1->lb_hash_config);
          }

          ASSERT (lb0->lb_n_buckets > 0);
          ASSERT (is_pow2 (lb0->lb_n_buckets));
          ASSERT (lb1->lb_n_buckets > 0);
          ASSERT (is_pow2 (lb1->lb_n_buckets));

          dpo0 = load_balance_get_bucket_i(lb0,
                                           (hash_c0 &
                                            (lb0->lb_n_buckets_minus_1)));
          dpo1 = load_balance_get_bucket_i(lb1,
                                           (hash_c1 &
                                            (lb1->lb_n_buckets_minus_1)));

          next0 = dpo0->dpoi_next_node;
          next1 = dpo1->dpoi_next_node;

          vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
          vnet_buffer (b1)->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;

          vlib_increment_combined_counter
              (cm, cpu_index, lbi0, 1,
               vlib_buffer_length_in_chain (vm, b0));
          vlib_increment_combined_counter
              (cm, cpu_index, lbi1, 1,
               vlib_buffer_length_in_chain (vm, b1));

          /*
           * pop the label that was just used in the lookup
           */
          vlib_buffer_advance(b0, sizeof(*h0));
          vlib_buffer_advance(b1, sizeof(*h1));

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_lookup_trace_t *tr = vlib_add_trace (vm, node,
                                                        b0, sizeof (*tr));
              tr->next_index = next0;
              tr->lb_index = lbi0;
              tr->lfib_index = lfib_index0;
              tr->hash = hash_c0;
              tr->label_net_byte_order = h0->label_exp_s_ttl;
          }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_lookup_trace_t *tr = vlib_add_trace (vm, node,
                                                        b1, sizeof (*tr));
              tr->next_index = next1;
              tr->lb_index = lbi1;
              tr->lfib_index = lfib_index1;
              tr->hash = hash_c1;
              tr->label_net_byte_order = h1->label_exp_s_ttl;
          }

          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
      {
          u32 lbi0, next0, lfib_index0, bi0, hash_c0;
          const mpls_unicast_header_t * h0;
          const load_balance_t *lb0;
          const dpo_id_t *dpo0;
          vlib_buffer_t * b0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          h0 = vlib_buffer_get_current (b0);

          lfib_index0 = vec_elt(mm->fib_index_by_sw_if_index,
                                vnet_buffer(b0)->sw_if_index[VLIB_RX]);

          lbi0 = mpls_fib_table_forwarding_lookup (lfib_index0, h0);
          lb0 = load_balance_get(lbi0);

          hash_c0 = vnet_buffer(b0)->ip.flow_hash = 0;
          if (PREDICT_FALSE(lb0->lb_n_buckets > 1))
          {
              hash_c0 = vnet_buffer (b0)->ip.flow_hash =
                  mpls_compute_flow_hash(h0, lb0->lb_hash_config);
          }

          ASSERT (lb0->lb_n_buckets > 0);
          ASSERT (is_pow2 (lb0->lb_n_buckets));

          dpo0 = load_balance_get_bucket_i(lb0,
                                           (hash_c0 &
                                            (lb0->lb_n_buckets_minus_1)));

          next0 = dpo0->dpoi_next_node;
          vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

          vlib_increment_combined_counter
              (cm, cpu_index, lbi0, 1,
               vlib_buffer_length_in_chain (vm, b0));

          /*
           * pop the label that was just used in the lookup
           */
          vlib_buffer_advance(b0, sizeof(*h0));

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_lookup_trace_t *tr = vlib_add_trace (vm, node,
                                                        b0, sizeof (*tr));
              tr->next_index = next0;
              tr->lb_index = lbi0;
              tr->lfib_index = lfib_index0;
              tr->hash = hash_c0;
              tr->label_net_byte_order = h0->label_exp_s_ttl;
          }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, mpls_lookup_node.index,
                               MPLS_ERROR_PKTS_DECAP, from_frame->n_vectors);
  return from_frame->n_vectors;
}

static char * mpls_error_strings[] = {
#define mpls_error(n,s) s,
#include "error.def"
#undef mpls_error
};

VLIB_REGISTER_NODE (mpls_lookup_node) = {
  .function = mpls_lookup,
  .name = "mpls-lookup",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = MPLS_N_ERROR,
  .error_strings = mpls_error_strings,

  .sibling_of = "ip4-lookup",

  .format_buffer = format_mpls_header,
  .format_trace = format_mpls_lookup_trace,
  .unformat_buffer = unformat_mpls_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_lookup_node, mpls_lookup)

typedef struct {
  u32 next_index;
  u32 lb_index;
  u32 hash;
} mpls_load_balance_trace_t;

static u8 *
format_mpls_load_balance_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_load_balance_trace_t * t = va_arg (*args, mpls_load_balance_trace_t *);

  s = format (s, "MPLS: next [%d], LB index %d hash %d",
              t->next_index, t->lb_index, t->hash);
  return s;
}

always_inline uword
mpls_load_balance (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  vlib_combined_counter_main_t * cm = &load_balance_main.lbm_via_counters;
  u32 n_left_from, n_left_to_next, * from, * to_next;
  u32 cpu_index = os_get_cpu_number();
  u32 next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next,
                           to_next, n_left_to_next);


      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          mpls_lookup_next_t next0, next1;
          const load_balance_t *lb0, *lb1;
          vlib_buffer_t * p0, *p1;
          u32 pi0, lbi0, hc0, pi1, lbi1, hc1;
          const mpls_unicast_header_t *mpls0, *mpls1;
          const dpo_id_t *dpo0, *dpo1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, STORE);
            vlib_prefetch_buffer_header (p3, STORE);

            CLIB_PREFETCH (p2->data, sizeof (mpls0[0]), STORE);
            CLIB_PREFETCH (p3->data, sizeof (mpls0[0]), STORE);
          }

          pi0 = to_next[0] = from[0];
          pi1 = to_next[1] = from[1];

          from += 2;
          n_left_from -= 2;
          to_next += 2;
          n_left_to_next -= 2;

          p0 = vlib_get_buffer (vm, pi0);
          p1 = vlib_get_buffer (vm, pi1);

          mpls0 = vlib_buffer_get_current (p0);
          mpls1 = vlib_buffer_get_current (p1);
          lbi0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
          lbi1 = vnet_buffer (p1)->ip.adj_index[VLIB_TX];

          lb0 = load_balance_get(lbi0);
          lb1 = load_balance_get(lbi1);

          /*
           * this node is for via FIBs we can re-use the hash value from the
           * to node if present.
           * We don't want to use the same hash value at each level in the recursion
           * graph as that would lead to polarisation
           */
          hc0 = vnet_buffer (p0)->ip.flow_hash = 0;
          hc1 = vnet_buffer (p1)->ip.flow_hash = 0;

          if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
          {
              if (PREDICT_TRUE (vnet_buffer(p0)->ip.flow_hash))
              {
                  hc0 = vnet_buffer(p0)->ip.flow_hash = vnet_buffer(p0)->ip.flow_hash >> 1;
              }
              else
              {
                  hc0 = vnet_buffer(p0)->ip.flow_hash = mpls_compute_flow_hash(mpls0, hc0);
              }
          }
          if (PREDICT_FALSE (lb1->lb_n_buckets > 1))
          {
              if (PREDICT_TRUE (vnet_buffer(p1)->ip.flow_hash))
              {
                  hc1 = vnet_buffer(p1)->ip.flow_hash = vnet_buffer(p1)->ip.flow_hash >> 1;
              }
              else
              {
                  hc1 = vnet_buffer(p1)->ip.flow_hash = mpls_compute_flow_hash(mpls1, hc1);
              }
          }

          dpo0 = load_balance_get_bucket_i(lb0, hc0 & (lb0->lb_n_buckets_minus_1));
          dpo1 = load_balance_get_bucket_i(lb1, hc1 & (lb1->lb_n_buckets_minus_1));

          next0 = dpo0->dpoi_next_node;
          next1 = dpo1->dpoi_next_node;

          vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
          vnet_buffer (p1)->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;

          vlib_increment_combined_counter
              (cm, cpu_index, lbi0, 1,
               vlib_buffer_length_in_chain (vm, p0));
          vlib_increment_combined_counter
              (cm, cpu_index, lbi1, 1,
               vlib_buffer_length_in_chain (vm, p1));

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_load_balance_trace_t *tr = vlib_add_trace (vm, node,
                                                              p0, sizeof (*tr));
              tr->next_index = next0;
              tr->lb_index = lbi0;
              tr->hash = hc0;
          }

          vlib_validate_buffer_enqueue_x2 (vm, node, next,
                                           to_next, n_left_to_next,
                                           pi0, pi1, next0, next1);
       }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          mpls_lookup_next_t next0;
          const load_balance_t *lb0;
          vlib_buffer_t * p0;
          u32 pi0, lbi0, hc0;
          const mpls_unicast_header_t *mpls0;
          const dpo_id_t *dpo0;

          pi0 = from[0];
          to_next[0] = pi0;
          from += 1;
          to_next += 1;
          n_left_to_next -= 1;
          n_left_from -= 1;

          p0 = vlib_get_buffer (vm, pi0);

          mpls0 = vlib_buffer_get_current (p0);
          lbi0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

          lb0 = load_balance_get(lbi0);

          hc0 = vnet_buffer (p0)->ip.flow_hash = 0;
          if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
          {
              if (PREDICT_TRUE (vnet_buffer(p0)->ip.flow_hash))
              {
                  hc0 = vnet_buffer(p0)->ip.flow_hash = vnet_buffer(p0)->ip.flow_hash >> 1;
              }
              else
              {
                  hc0 = vnet_buffer(p0)->ip.flow_hash = mpls_compute_flow_hash(mpls0, hc0);
              }
          }

          dpo0 = load_balance_get_bucket_i(lb0, hc0 & (lb0->lb_n_buckets_minus_1));

          next0 = dpo0->dpoi_next_node;
          vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

          vlib_increment_combined_counter
              (cm, cpu_index, lbi0, 1,
               vlib_buffer_length_in_chain (vm, p0));

          vlib_validate_buffer_enqueue_x1 (vm, node, next,
                                           to_next, n_left_to_next,
                                           pi0, next0);
        }

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (mpls_load_balance_node) = {
  .function = mpls_load_balance,
  .name = "mpls-load-balance",
  .vector_size = sizeof (u32),
  .sibling_of = "mpls-lookup",

  .format_trace = format_mpls_load_balance_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_load_balance_node, mpls_load_balance)
